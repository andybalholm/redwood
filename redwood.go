// Redwood is an internet content-filtering program. 
// It is designed to replace and improve on DansGuardian 
// as the core of the Security Appliance internet filter. 
package main

import (
	"bufio"
	"flag"
	"fmt"
	"http"
	"os"
)

var configFile = flag.String("c", "/etc/redwood/redwood.conf", "configuration file path")

func main() {
	flag.Parse()
	loadConfiguration()

	br := bufio.NewReader(os.Stdin)
	for {
		line, _, err := br.ReadLine()
		if err != nil {
			break
		}

		u, err := http.ParseURL(string(line))
		matches := URLRules.MatchingRules(u)
		for _, s := range matches {
			fmt.Println(s)
		}
	}
}
