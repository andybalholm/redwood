package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var listenerChan = make(chan net.Listener)

var activeConnections sync.WaitGroup

func init() {
	go watchForSIGTERM()
}

func watchForSIGTERM() {
	var listeners []net.Listener
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM)

	for {
		select {
		case l := <-listenerChan:
			listeners = append(listeners, l)

		case <-sigChan:
			log.Println("Received SIGTERM")
			for _, ln := range listeners {
				ln.Close()
			}
			if *pidfile != "" {
				os.Remove(*pidfile)
			}
			activeConnections.Wait()
			os.Exit(0)
		}
	}
}
