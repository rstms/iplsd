package cmd

import (
	"flag"
	"github.com/rstms/go-daemon"
	"log"
	"os"
	"syscall"
)

type DaemonMain func()

var DaemonizeDisabled = false

var (
	signalFlag = flag.String("s", "", `send signal:
    stop - shutdown
    reload - reload config
    `)
	shutdown = make(chan struct{})
	reload   = make(chan struct{})
)

func stopHandler(sig os.Signal) error {
	log.Println("daemonize: received stop signal, sending shutdown")
	shutdown <- struct{}{}
	return daemon.ErrStop
}

func reloadHandler(sig os.Signal) error {
	log.Println("daemonize: received reload signal")
	return nil
}

func Daemonize(main DaemonMain, logFilename string) {

	if DaemonizeDisabled {
		main()
		return
	}

	daemon.AddCommand(daemon.StringFlag(signalFlag, "stop"), syscall.SIGTERM, stopHandler)
	daemon.AddCommand(daemon.StringFlag(signalFlag, "reload"), syscall.SIGHUP, reloadHandler)

	ctx := &daemon.Context{
		LogFileName: logFilename,
		LogFilePerm: 0600,
		WorkDir:     "/",
		Umask:       007,
	}

	if len(daemon.ActiveFlags()) > 0 {
		d, err := ctx.Search()
		if err != nil {
			log.Fatalf("daemonize: failed sending signal: %v", err)
		}
		daemon.SendCommands(d)
		return
	}

	child, err := ctx.Reborn()
	if err != nil {
		log.Fatalf("daemonize: Fork failed: %v", err)
	}

	if child != nil {
		return
	}
	defer ctx.Release()

	go func() {
		go main()
		<-shutdown
		log.Println("daemonize: received shutdown, exiting")
	}()

	err = daemon.ServeSignals()
	if err != nil {
		log.Fatalf("daemonize: ServeSignals failed: %v", err)
	}
}
