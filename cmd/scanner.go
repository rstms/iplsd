package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/spf13/viper"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	LogFile        string
	AddressFile    string
	TimeoutDir     string
	AddressTimeout time.Duration
	TickInterval   time.Duration
	Patterns       []*regexp.Regexp
	stop           chan struct{}
	process        *os.Process
	AddCommand     string
	AddArgs        []string
	DeleteCommand  string
	DeleteArgs     []string
}

var IP_PATTERN = regexp.MustCompile(`((?:\d{1,3}\.){3}\d{1,3})`)

func NewScanner(AddressFile, TimeoutDir string, patterns []string) (*Scanner, error) {
	timeout, err := time.ParseDuration(viper.GetString("timeout_seconds") + "s")
	if err != nil {
		return nil, fmt.Errorf("ParseDuration (timeout_seconds) failed: %v", err)
	}
	interval, err := time.ParseDuration(viper.GetString("interval_seconds") + "s")
	if err != nil {
		return nil, fmt.Errorf("ParseDuration (interval_seconds) failed: %v", err)
	}
	s := Scanner{
		AddressFile:    AddressFile,
		TimeoutDir:     TimeoutDir,
		Patterns:       []*regexp.Regexp{},
		TickInterval:   interval,
		AddressTimeout: timeout,
		stop:           make(chan struct{}),
	}

	addCommand := strings.Split(viper.GetString("add_command"), " ")
	s.AddCommand = addCommand[0]
	if len(addCommand) > 1 {
		s.AddArgs = addCommand[1:]
	}

	deleteCommand := strings.Split(viper.GetString("delete_command"), " ")
	s.DeleteCommand = deleteCommand[0]
	if len(deleteCommand) > 1 {
		s.DeleteArgs = deleteCommand[1:]
	}

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed regex compile: %v", err)
		}
		s.Patterns = append(s.Patterns, re)
	}
	if !IsDir(TimeoutDir) {
		log.Printf("creating timeout directory: '%s'\n", TimeoutDir)
		err := os.Mkdir(TimeoutDir, 0700)
		if err != nil {
			return nil, err
		}
	}
	if !IsFile(AddressFile) {
		log.Printf("creating address file: '%s'\n", AddressFile)
		err := os.WriteFile(AddressFile, []byte(""), 0600)
		if err != nil {
			return nil, err
		}

	}
	addrs, err := s.readAddressFile()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if !IsFile(filepath.Join(TimeoutDir, addr)) {
			err := s.writeTimeoutFile(addr)
			if err != nil {
				return nil, err
			}
		}
	}
	return &s, nil
}

func (s *Scanner) writeTimeoutFile(addr string) error {
	expiration := time.Now().Add(s.AddressTimeout)
	data, err := expiration.MarshalText()
	if err != nil {
		return fmt.Errorf("failed marshalling expiration: %v", err)
	}
	filename := filepath.Join(s.TimeoutDir, addr)
	err = os.WriteFile(filename, data, 0600)
	if err != nil {
		return err
	}
	return nil
}

func (s *Scanner) deleteTimeoutFile(addr string) error {
	filename := filepath.Join(s.TimeoutDir, addr)
	err := os.Remove(filename)
	if err != nil {
		return err
	}
	return nil
}

func (s *Scanner) Scan(filename string) error {
	s.LogFile = filename
	log.Println("scanner: started")
	defer log.Println("scanner: stopped")
	var wg sync.WaitGroup
	wg.Add(2)
	rechan := make(chan error, 1)
	go func() {
		defer wg.Done()
		rechan <- s.reaper()
	}()
	sechan := make(chan error, 1)
	go func() {
		defer wg.Done()
		sechan <- s.scanner()
	}()

	wg.Wait()
	log.Printf("scan wg.Wait complete\n")

	err := <-rechan
	if err != nil {
		return err
	}
	err = <-sechan
	if err != nil {
		return err
	}
	return nil
}

func (s *Scanner) reaper() error {
	log.Println("reaper: started")
	defer log.Println("reaper: stopped")
	defer func() {
		if s.process != nil {
			err := s.process.Kill()
			if err != nil {
				log.Printf("reaper: failed killing tail process: %v", err)
			}
		}
	}()
	ticker := time.NewTicker(s.TickInterval)
	defer ticker.Stop()
	for {
		select {
		case _, ok := <-s.stop:
			if !ok {
				log.Println("reaper: received stop")
				return nil
			}
		case <-ticker.C:
			log.Println("reaper: checking expirations")
			entries, err := os.ReadDir(s.TimeoutDir)
			if err != nil {
				return err
			}
			expiredAddrs := []string{}
			for _, entry := range entries {
				if entry.Type().IsRegular() {
					addr := entry.Name()
					filename := filepath.Join(s.TimeoutDir, addr)
					timeData, err := os.ReadFile(filename)
					if err != nil {
						return err
					}
					var expiration time.Time
					err = expiration.UnmarshalText(timeData)
					if err != nil {
						return fmt.Errorf("reaper: failed umarshalling expiration from '%s': %v", filename, err)
					}
					if time.Now().Compare(expiration) >= 0 {
						expiredAddrs = append(expiredAddrs, addr)
					} else {
						log.Printf("reaper: active %s %s\n", addr, string(timeData))
					}
				}
			}

			for _, addr := range expiredAddrs {
				action, err := s.removeAddress(addr)
				if err != nil {
					return fmt.Errorf("reaper: removeAddress failed: %v", err)
				}
				err = s.deleteTimeoutFile(addr)
				if err != nil {
					return err
				}
				log.Printf("reaper: expired IP %s %s %s\n", addr, action, s.AddressFile)
			}
		}

	}
}

func (s *Scanner) scanner() error {
	log.Printf("scanner: monitoring log file: %s\n", s.LogFile)
	defer log.Println("scanner: stopped")
	defer func() {
		close(s.stop)
	}()

	cmd := exec.Command("tail", "-f", s.LogFile)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("scanner: failed opening stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("scanner: failed opening stderr pipe: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("scanner: failed spawning tail command: %v", err)
	}
	s.process = cmd.Process

	echan := make(chan string, 1)
	go func() {
		defer close(echan)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			echan <- scanner.Text()
		}
		err := scanner.Err()
		if err != nil {
			log.Printf("scanner: failed reading tail stderr: %v", err)
		}
	}()

	ochan := make(chan string, 1)
	go func() {
		defer close(ochan)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			ochan <- scanner.Text()
		}
		err = scanner.Err()
		if err != nil {
			log.Printf("scanner: failed reading tail pipe: %v", err)
		}
	}()

	eclosed := false
	oclosed := false

	for !(eclosed && oclosed) {
		select {
		case line, ok := <-ochan:
			if !ok {
				log.Println("scanner: output chan closed")
				oclosed = true
			} else {
				for _, pattern := range s.Patterns {
					match := pattern.FindStringSubmatch(line)
					if len(match) > 1 {
						addr := match[1]
						// update or create the timeout file
						err := s.writeTimeoutFile(addr)
						if err != nil {
							return fmt.Errorf("scanner: writeTimeoutFile: %v", err)
						}
						// add the address to the AddressFile if not present
						action, err := s.addAddress(addr)
						if err != nil {
							return fmt.Errorf("scanner: addAddress: %v", err)
						}
						log.Printf("scanner: IP %s %s %s\n", addr, action, s.AddressFile)
					}
				}
			}

		case line, ok := <-echan:
			if !ok {
				log.Println("scanner: error chan closed")
				eclosed = true
			} else {
				log.Printf("scanner: tail: %s\n", line)
			}
		}
	}

	err = cmd.Wait()
	s.process = nil
	if err != nil {
		return fmt.Errorf("scanner: tail subprocess failed: %v", err)
	}
	return nil
}

func (s *Scanner) readAddressFile() ([]string, error) {
	addrs := []string{}
	file, err := os.Open(s.AddressFile)
	if err != nil {
		return []string{}, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		addr := strings.TrimSpace(scanner.Text())
		if addr != "" {
			if IP_PATTERN.MatchString(addr) {
				addrs = append(addrs, addr)
			} else {
				return nil, fmt.Errorf("unexpected address '%s' found in address list file: %s", addr, s.AddressFile)
			}
		}
	}
	err = scanner.Err()
	if err != nil {
		return []string{}, fmt.Errorf("failed reading address file '%s': %v", s.AddressFile, err)
	}
	return addrs, nil
}

// add address if not present, return true if address already exists
func (s *Scanner) addAddress(addr string) (string, error) {
	if s.AddCommand != "" {
		err := s.exec(s.AddCommand, append(s.AddArgs, addr))
		if err != nil {
			return "", err
		}
	}
	addrs, err := s.readAddressFile()
	if err != nil {
		return "", err
	}
	if slices.Contains(addrs, addr) {
		return "already present in", nil
	}
	addrs = append(addrs, addr)
	err = os.WriteFile(s.AddressFile, []byte(strings.Join(addrs, "\n")+"\n"), 0600)
	if err != nil {
		return "", err
	}
	return "added to", nil
}

// add address if not present, return true if address already exists
func (s *Scanner) removeAddress(addr string) (string, error) {
	if s.DeleteCommand != "" {
		err := s.exec(s.DeleteCommand, append(s.DeleteArgs, addr))
		if err != nil {
			return "", err
		}
	}
	addrs, err := s.readAddressFile()
	if err != nil {
		return "", err
	}
	if !slices.Contains(addrs, addr) {
		return "not present in", nil
	}
	i := slices.Index(addrs, addr)
	addrs = slices.Delete(addrs, i, i+1)
	err = os.WriteFile(s.AddressFile, []byte(strings.Join(addrs, "\n")+"\n"), 0600)
	if err != nil {
		return "", err
	}
	return "deleted from", nil
}

func (s *Scanner) exec(command string, args []string) error {
	log.Printf("scanner: %s %s\n", command, strings.Join(args, " "))
	cmd := exec.Command(command, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = bufio.NewWriter(&stdout)
	cmd.Stderr = bufio.NewWriter(&stderr)
	err := cmd.Run()
	if err != nil {
		return err
	}
	if stdout.Len() > 0 {
		log.Printf("[%s]: %s", command, stdout.String())
	}
	if stderr.Len() > 0 {
		log.Printf("[%s]: %s", command, stderr.String())
	}
	return nil
}
