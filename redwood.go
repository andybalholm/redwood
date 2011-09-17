// Redwood is an internet content-filtering program. 
// It is designed to replace and improve on DansGuardian 
// as the core of the Security Appliance internet filter. 
package main

import (
	"flag"
	"go-icap.googlecode.com/hg"
)

var configFile = flag.String("c", "/etc/redwood/redwood.conf", "configuration file path")
var testURL = flag.String("test", "", "URL to test instead of running ICAP server")

func main() {
	flag.Parse()
	loadConfiguration()

	if *testURL != "" {
		runURLTest(*testURL)
		return
	}

	icap.HandleFunc("/reqmod", handleRequest)
	icap.ListenAndServe(":1344", nil)
}
