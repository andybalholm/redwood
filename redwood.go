// Redwood is an internet content-filtering program. 
// It is designed to replace and improve on DansGuardian 
// as the core of the Security Appliance internet filter. 
package main

import (
	"code.google.com/p/go-icap"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
)

var testURL = flag.String("test", "", "URL to test instead of running ICAP server")
var cpuProfile = flag.String("cpuprofile", "", "write cpu profile to file")
var cores = flag.Int("cores", 1, "number of CPU cores to use")

func main() {
	loadConfiguration()

	runtime.GOMAXPROCS(*cores)

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	go func() {
		for {
			select {
			case sig := <-signal.Incoming:
				switch sig.(os.UnixSignal) {
				case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
					log.Println("Terminating on signal", sig)
					if *cpuProfile != "" {
						pprof.StopCPUProfile()
					}
					os.Exit(0)
				}
			}
		}
	}()

	startWebServer()

	icap.HandleFunc("/reqmod", handleRequest)
	icap.HandleFunc("/respmod", handleResponse)
	icap.ListenAndServe(":1344", nil)
}
