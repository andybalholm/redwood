package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// support for reloading configuration without restarting Redwood

var configRequests = make(chan chan *config)

// getConfig returns the current configuration.
func getConfig() *config {
	ch := make(chan *config)
	configRequests <- ch
	return <-ch
}

var (
	// shutdownChan is closed to indicate that the server is shutting down, and
	// no more connections should be accepted.
	shutdownChan = make(chan struct{})

	hupChan = make(chan os.Signal, 1)

	activeConnections sync.WaitGroup
)

// manageConfig manages Redwood's configuration, reloading it when SIGHUP is received.
func manageConfig() {
	conf, err := loadConfiguration()
	if err != nil {
		log.Fatal(err)
	}

	signal.Notify(hupChan, syscall.SIGHUP)

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGTERM)

	accessLog := NewCSVLog(conf.AccessLog)
	tlsLog := NewCSVLog(conf.TLSLog)

	conf.startWebServer()

	for {
		select {
		case req := <-configRequests:
			req <- conf

		case data := <-accessLogChan:
			accessLog.Log(data)

		case data := <-tlsLogChan:
			tlsLog.Log(data)

		case <-hupChan:
			log.Println("Received SIGHUP")
			newConf, err := loadConfiguration()
			if err != nil {
				log.Println("Error reloading configuration:", err)
				break
			}

			conf = newConf

			accessLog.Close()
			tlsLog.Close()
			accessLog = NewCSVLog(conf.AccessLog)
			tlsLog = NewCSVLog(conf.TLSLog)

			conf.startWebServer()
			openPerUserPorts(conf.CustomPorts)

		case <-termChan:
			log.Println("Received SIGTERM")
			close(shutdownChan)
			if conf.PIDFile != "" {
				os.Remove(conf.PIDFile)
			}
			go func() {
				// Allow 20 seconds for active connections to finish.
				time.Sleep(20 * time.Second)
				os.Exit(0)
			}()
			// Or exit when all active connections have finished.
			activeConnections.Wait()
			os.Exit(0)
		}
	}
}
