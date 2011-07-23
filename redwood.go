// Redwood is an internet content-filtering program. 
// It is designed to replace and improve on DansGuardian 
// as the core of the Security Appliance internet filter. 
package main

import (
	"flag"
	"fmt"
)

var configFile = flag.String("c", "/etc/redwood/redwood.conf", "configuration file path")

func main() {
	flag.Parse()
	loadConfiguration()

	for _, c := range categories {
		fmt.Println("name:", c.name)
		fmt.Println("description:", c.description)
		fmt.Print("action: ")
		switch c.action {
		case BLOCK:
			fmt.Println("block")
		case IGNORE:
			fmt.Println("ignore")
		case ALLOW:
			fmt.Println("allow")
		}

		fmt.Println()

		for rule, w := range c.weights {
			if w.maxPoints == 0 {
				fmt.Println(rule, w.points)
			} else {
				fmt.Println(rule, w.points, w.maxPoints)
			}
		}
	}
}
