// The dg-convert command takes a Dansguardian weighted phrase list on standard
// input, and prints it in Redwood format on standard output. Any rules with
// phrases joined by commas are dropped.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/transform"
)

var cs = flag.String("charset", "utf-8", "input encoding")

func main() {
	flag.Parse()

	var in io.Reader
	in = os.Stdin

	if *cs != "utf-8" {
		e, _ := charset.Lookup(*cs)
		in = transform.NewReader(in, e.NewDecoder())
	}

	s := bufio.NewScanner(in)
	for s.Scan() {
		line := s.Text()
		if strings.Contains(line, ">,<") {
			continue
		}

		endPhrase := strings.Index(line, "><")
		if endPhrase != -1 {
			phrase := line[:endPhrase+1]
			rest := line[endPhrase+2:]
			endScore := strings.Index(rest, ">")
			if endScore != -1 {
				score := rest[:endScore]
				rest = strings.TrimSpace(rest[endScore+1:])
				fmt.Println(phrase, score, rest)
				continue
			}
		}

		fmt.Println(line)
	}
	if err := s.Err(); err != nil {
		log.Println(err)
	}
}
