package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Scanner struct {
	LogFile        string
	AddressFile    string
	TimeoutDir     string
	AddressTimeout time.Duration
	TickInterval   time.Duration
	Patterns       []*regexp.Regexp
	AddCommand     string
	AddArgs        []string
	DeleteCommand  string
	DeleteArgs     []string
	tail           *exec.Cmd
	tailStdout     chan string
	tailStderr     chan string
	reaperErr      chan error
	scannerErr     chan error
	handlerErr     chan error
	scannerStop    chan struct{}
	reaperStop     chan struct{}
	handlerStop    chan struct{}
	started        bool
	wg             sync.WaitGroup
	verbose        bool
	shutdownLock   sync.Mutex
	active         sync.Map
}

var IP_PATTERN = regexp.MustCompile(`((?:\d{1,3}\.){3}\d{1,3})`)

func NewScanner(logFile, AddressFile, TimeoutDir string, patterns []string) (*Scanner, error) {
	timeout, err := time.ParseDuration(ViperGetString("timeout_seconds") + "s")
	if err != nil {
		return nil, fmt.Errorf("ParseDuration (timeout_seconds) failed: %v", err)
	}
	interval, err := time.ParseDuration(ViperGetString("interval_seconds") + "s")
	if err != nil {
		return nil, fmt.Errorf("ParseDuration (interval_seconds) failed: %v", err)
	}
	s := Scanner{
		AddressFile:    AddressFile,
		TimeoutDir:     TimeoutDir,
		Patterns:       []*regexp.Regexp{},
		TickInterval:   interval,
		AddressTimeout: timeout,
		LogFile:        logFile,
		reaperStop:     make(chan struct{}, 1),
		reaperErr:      make(chan error, 1),
		scannerStop:    make(chan struct{}, 1),
		scannerErr:     make(chan error, 1),
		handlerStop:    make(chan struct{}, 1),
		handlerErr:     make(chan error, 1),
		tailStdout:     make(chan string, 1),
		tailStderr:     make(chan string, 1),
		verbose:        ViperGetBool("verbose"),
	}

	addCommand := strings.Split(ViperGetString("add_command"), " ")
	s.AddCommand = addCommand[0]
	if len(addCommand) > 1 {
		s.AddArgs = addCommand[1:]
	}

	deleteCommand := strings.Split(ViperGetString("delete_command"), " ")
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
	if ViperGetBool("verbose") {
		log.Println(FormatJSON(s))
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

func (s *Scanner) shutdown(caller string) {
	if s.verbose {
		log.Printf("shutdown[%s]: awaiting lock\n", caller)
	}
	s.shutdownLock.Lock()
	if s.verbose {
		log.Printf("shutdown[%s]: got lock", caller)
	}
	defer func() {
		if s.verbose {
			log.Printf("shutdown[%s]: exiting", caller)
		}
		s.shutdownLock.Unlock()
	}()

	firstCaller, ok := s.active.Load("shutdown")
	if ok {
		if s.verbose {
			log.Printf("shutdown[%s]: already called by %s", caller, firstCaller)
		}
		return
	}
	s.active.Store("shutdown", caller)

	if s.verbose {
		log.Printf("shutdown[%s]", caller)
	}

	if s.tail == nil {
		if s.verbose {
			log.Printf("shutdown[%s]: tail process inactive", caller)
		}
	} else {
		if s.tail.Process != nil {
			if s.verbose {
				log.Printf("shutdown[%s]: killing tail process %d\n", caller, s.tail.Process.Pid)
			}
			err := s.tail.Process.Kill()
			if err != nil {
				log.Printf("shutdown[%s]: tail kill failed: %v", caller, Fatal(err))
			}
			err = s.tail.Wait()
			if err != nil {
				log.Printf("shutdown[%s]: tail wait returned: %v", caller, err)
			}
		}
		s.tail = nil
	}
	_, ok = s.active.Load("reaper")
	if ok {
		log.Printf("shutdown[%s]: sendingReaperStop", caller)
		s.reaperStop <- struct{}{}
	} else if s.verbose {
		log.Printf("shutdown[%s]: reaper already stopped", caller)
	}
	_, ok = s.active.Load("scanner")
	if ok {
		log.Printf("shutdown[%s]: sending scannerStop", caller)
		s.scannerStop <- struct{}{}
	} else if s.verbose {
		log.Printf("shutdown[%s]: scanner already stopped", caller)
	}
	_, ok = s.active.Load("handler")
	if ok {
		log.Printf("shutdown[%s]: sending handlerStop", caller)
		s.handlerStop <- struct{}{}
	} else if s.verbose {
		log.Printf("shutdown[%s]: handler already stopped", caller)
	}
}

func (s *Scanner) reaper(startChan chan struct{}) error {
	log.Println("reaper: starting")
	defer func() {
		log.Println("reaper: exiting")
		s.active.Delete("reaper")
		s.shutdown("reaper")
	}()
	s.active.Store("reaper", true)
	ticker := time.NewTicker(s.TickInterval)
	startChan <- struct{}{}
	defer ticker.Stop()
	for {
		select {
		case _, ok := <-s.reaperStop:
			if ok {
				log.Println("reaper: received reaperStop")
				return nil
			} else {
				log.Println("reaper: reaperStop has closed")
				return nil
			}
		case <-ticker.C:
			log.Println("reaper: checking expirations")
			entries, err := os.ReadDir(s.TimeoutDir)
			if err != nil {
				return Fatal(err)
			}
			expiredAddrs := []string{}
			for _, entry := range entries {
				if entry.Type().IsRegular() {
					addr := entry.Name()
					filename := filepath.Join(s.TimeoutDir, addr)
					timeData, err := os.ReadFile(filename)
					if err != nil {
						return Fatal(err)
					}
					var expiration time.Time
					err = expiration.UnmarshalText(timeData)
					if err != nil {
						return Fatalf("reaper: failed umarshalling expiration from '%s': %v", filename, err)
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
					return Fatalf("reaper: removeAddress failed: %v", err)
				}
				err = s.deleteTimeoutFile(addr)
				if err != nil {
					return Fatal(err)
				}
				log.Printf("reaper: expired IP %s %s %s\n", addr, action, s.AddressFile)
			}
		}

	}
	return Fatalf("unexpected exit")
}

func (s *Scanner) scanner(startChan chan struct{}) error {

	defer func() {
		log.Println("scanner: exiting")
		s.active.Delete("scanner")
		s.shutdown("scanner")
	}()
	log.Printf("scanner: started monitoring log file: %s\n", s.LogFile)
	s.active.Store("scanner", true)

	s.tail = exec.Command("tail", "-f", s.LogFile)
	stdout, err := s.tail.StdoutPipe()
	if err != nil {
		return fmt.Errorf("scanner: failed opening stdout pipe: %v", err)
	}
	stderr, err := s.tail.StderrPipe()
	if err != nil {
		return fmt.Errorf("scanner: failed opening stderr pipe: %v", err)
	}
	err = s.tail.Start()
	if err != nil {
		return fmt.Errorf("scanner: failed spawning tail command: %v", err)
	}

	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		defer close(s.tailStderr)
		if s.verbose {
			defer log.Printf("scanner: tail stderr reader exiting")
			log.Printf("scanner: tail stderr reader started")
		}
		reader := bufio.NewReader(stderr)
		for {
			buf, err := reader.ReadString('\n')
			if err != nil {
				log.Printf("scanner: tailpipe stderr: %v", err)
				return
			}
			line := strings.TrimSpace(buf)
			s.tailStderr <- line
		}
	}()

	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		defer close(s.tailStdout)
		if s.verbose {
			defer log.Printf("scanner: tail stdout reader exiting")
			log.Printf("scanner: tail stdout reader started")
		}
		reader := bufio.NewReader(stdout)
		for {
			buf, err := reader.ReadString('\n')
			if err != nil {
				log.Printf("scanner: tailpipe stdout: %v", err)
				return
			}
			line := strings.TrimSpace(buf)
			s.tailStdout <- line
		}
	}()

	startChan <- struct{}{}
	stderrOpen := true
	stdoutOpen := true
	for stderrOpen || stdoutOpen {
		select {
		case line, ok := <-s.tailStdout:
			if !ok {
				if stdoutOpen && s.verbose {
					log.Println("scanner: stdout tailpipe has closed")
				}
				stdoutOpen = false
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

		case line, ok := <-s.tailStderr:
			if !ok {
				if stderrOpen && s.verbose {
					log.Println("scanner: stderr tailpipe has closed")
				}
				stderrOpen = false
			} else {
				log.Printf("scanner: tail: %s\n", line)
			}
		}
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

func (s *Scanner) handler(startChan chan struct{}) error {
	defer func() {
		log.Println("handler: exiting")
		s.active.Delete("handler")
		s.shutdown("handler")
	}()
	log.Println("handler: started")
	s.active.Store("handler", true)
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, syscall.SIGINT)
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	if s.verbose {
		fmt.Println("CTRL-C to exit")
	}
	startChan <- struct{}{}
	for {
		select {
		case <-sigint:
			log.Println("handler: received SIGINT")
			return nil
		case <-sigterm:
			log.Println("handler: received SIGTERM")
			return nil
		case _, ok := <-s.handlerStop:
			if ok {
				log.Println("handler: received handlerStop")
				return nil
			} else {
				log.Println("handler: handlerStop has closed")
				return nil
			}
		}
	}
	return Fatalf("unexpected exit")
}

func (s *Scanner) Start() error {
	reaperStarted := make(chan struct{})
	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		s.reaperErr <- s.reaper(reaperStarted)
	}()
	<-reaperStarted
	scannerStarted := make(chan struct{})
	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		s.scannerErr <- s.scanner(scannerStarted)
	}()
	<-scannerStarted
	handlerStarted := make(chan struct{})
	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		s.handlerErr <- s.handler(handlerStarted)
	}()
	<-handlerStarted
	s.started = true
	return nil
}

func (s *Scanner) Run() error {
	if !s.started {
		err := s.Start()
		if err != nil {
			return Fatal(err)
		}
	}

	if s.verbose {
		log.Println("run: waiting on goprocs...")
	}
	s.wg.Wait()
	if s.verbose {
		log.Println("run: all goprocs have exited")
	}
	var ret error
	for done := false; !done; {
		select {
		case err, ok := <-s.reaperErr:
			if ok {
				if err != nil {
					if ret == nil {
						ret = err
					} else {
						log.Printf("reaper: %v", err)
					}
				}
			}
		case err, ok := <-s.scannerErr:
			if ok {
				if err != nil {
					if ret == nil {
						ret = err
					} else {
						log.Printf("scanner: %v", err)
					}
				}
			}
		case err, ok := <-s.handlerErr:
			if ok {
				if err != nil {
					if ret == nil {
						ret = err
					} else {
						log.Printf("handler: %v", err)
					}
				}
			}
		default:
			done = true
		}
	}

	close(s.reaperErr)
	close(s.scannerErr)
	close(s.handlerErr)
	return ret
}

func (s *Scanner) Stop() error {
	s.shutdown("stop")
	close(s.reaperStop)
	close(s.scannerStop)
	close(s.handlerStop)
	return nil
}
