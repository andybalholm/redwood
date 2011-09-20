// Redwood is an internet content-filtering program. 
// It is designed to replace and improve on DansGuardian 
// as the core of the Security Appliance internet filter. 
package main

import (
	"flag"
	"go-icap.googlecode.com/hg"
	"log"
	"os"
	"runtime/pprof"
)

var configFile = flag.String("c", "/etc/redwood/redwood.conf", "configuration file path")
var testURL = flag.String("test", "", "URL to test instead of running ICAP server")
var cpuProfile = flag.String("cpuprofile", "", "write cpu profile to file")

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

	loadConfiguration()

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	icap.HandleFunc("/reqmod", handleRequest)
	icap.HandleFunc("/respmod", handleResponse)
	icap.ListenAndServe(":1344", nil)
}
