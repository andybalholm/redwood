// Redwood is an internet content-filtering program. 
// It is designed to replace and improve on DansGuardian 
// as the core of the Security Appliance internet filter. 
package main

import (
	"flag"
	"go-icap.googlecode.com/hg"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"syscall"
)

var configFile = flag.String("c", "/etc/redwood/redwood.conf", "configuration file path")
var testURL = flag.String("test", "", "URL to test instead of running ICAP server")
var cpuProfile = flag.String("cpuprofile", "", "write cpu profile to file")
var cores = flag.Int("cores", 1, "number of CPU cores to use")

func main() {
	flag.Parse()

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	runtime.GOMAXPROCS(*cores)

	loadConfiguration()

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

	http.Handle("/", http.FileServer(http.Dir(staticFilesDir)))
	loadCGIHandlers()

	icap.HandleFunc("/reqmod", handleRequest)
	icap.HandleFunc("/respmod", handleResponse)
	icap.ListenAndServe(":1344", nil)
}

func loadCGIHandlers() {
	dir, err := os.Open(cgiBin)
	if err != nil {
		log.Println("Could not open CGI directory:", err)
		return
	}
	defer dir.Close()

	info, err := dir.Readdir(0)
	if err != nil {
		log.Println("Could not read CGI directory:", err)
		return
	}

	for _, fi := range info {
		if fi.IsRegular() && (fi.Permission()&0100 != 0) {
			// It's an executable file.
			name := "/" + fi.Name
			scriptPath := filepath.Join(cgiBin, fi.Name)
			http.Handle(name, &cgi.Handler{
				Path: scriptPath,
			})
		}
	}
}
