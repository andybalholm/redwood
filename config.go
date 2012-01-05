package main

// functions for reading configuration files

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
)

// minimum total bad points to block a page
var blockThreshold = flag.Int("threshold", 0, "minimum score from blocked categories to block a page")

var categoriesDir = flag.String("categories", "", "path to configuration files for categories")

// locations for files for built-in web server
var staticFilesDir = flag.String("static-files-dir", "", "path to static files for built-in web server")
var cgiBin = flag.String("cgi-bin", "", "path to CGI files for built-in web server")
var blockPage = flag.String("blockpage", "", "path to template for block page")

var URLRules = newURLMatcher()

// readConfigFile reads the specified configuration file.
// For each line of the form "key value" or "key = value", it sets the flag
// variable named key to a value of value.
func readConfigFile(filename string) {
	f, err := os.Open(filename)
	if err != nil {
		log.Println("Error reading config file:", err)
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Println("Error reading config file:", err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		keyEnd := strings.IndexAny(line, " \t=")
		if keyEnd == -1 {
			keyEnd = len(line)
		}
		key := line[:keyEnd]
		line = line[keyEnd:]

		// Skip the space and/or equal sign.
		line = strings.TrimSpace(line)
		if line != "" && line[0] == '=' {
			line = strings.TrimSpace(line[1:])
		}

		var value string
		if line == "" {
			value = ""
		} else if line[0] == '"' {
			n, err := fmt.Sscanf(line, "%q", &value)
			if n != 1 || err != nil {
				log.Println("Improperly-quoted value in config file:", line)
			}
			continue
		} else {
			sharp := strings.Index(line, "#")
			if sharp != -1 {
				line = strings.TrimSpace(line[:sharp])
			}
			value = line
		}

		err = flag.Set(key, value)
		if err != nil {
			log.Println("Could not set", key, "to", value, ":", err)
		}
	}
}

func loadConfiguration() {
	readConfigFile(*configFile)

	configDir, _ := path.Split(*configFile)

	if *blockPage == "" {
		*blockPage = path.Join(configDir, "block.html")
	}
	loadBlockPageTemplate(*blockPage)

	if *staticFilesDir == "" {
		*staticFilesDir = path.Join(configDir, "static/")
	}

	if *cgiBin == "" {
		*cgiBin = path.Join(configDir, "cgi")
	}

	if *categoriesDir == "" {
		*categoriesDir = path.Join(configDir, "categories")
	}
	loadCategories(*categoriesDir)

	collectRules()
}

// configReader is a wrapper for reading a configuration file a line at a time,
// discarding comments and excess whitespace.
type configReader struct {
	r      *bufio.Reader
	LineNo int
}

func newConfigReader(r io.Reader) *configReader {
	return &configReader{r: bufio.NewReader(r)}
}

func (cr *configReader) ReadLine() (line string, err error) {
	for {
		b, isPrefix, err := cr.r.ReadLine()
		if err != nil {
			return "", err
		}

		cr.LineNo++

		if isPrefix {
			c := make([]byte, len(b), len(b)*2)
			copy(c, b)
			for isPrefix && err == nil {
				b, isPrefix, err = cr.r.ReadLine()
				c = append(c, b...)
			}
			b = c
		}

		if sharp := bytes.IndexByte(b, '#'); sharp != -1 {
			b = b[:sharp]
		}
		b = bytes.TrimSpace(b)

		if len(b) > 0 {
			return string(b), nil
		}
	}
	panic("unreachable")
}

// collectRules collects the rules from all the categories and adds
// them to URLRules and phraseRules.
func collectRules() {
	for _, c := range categories {
		for rule, _ := range c.weights {
			if rule.t == contentPhrase {
				addPhrase(rule)
			} else {
				URLRules.AddRule(rule)
			}
		}
	}
	findFallbackNodes(0, nil)
}
