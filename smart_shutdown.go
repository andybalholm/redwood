package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
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
			conf := getConfig()
			if conf.PIDFile != "" {
				os.Remove(conf.PIDFile)
			}
			go func() {
				// Stop after 24 hours even if the connections aren't closed.
				time.Sleep(24 * time.Hour)
				os.Exit(0)
			}()
			activeConnections.Wait()
			os.Exit(0)
		}
	}
}
