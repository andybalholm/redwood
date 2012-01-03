package main

// functions for reading configuration files

import (
	"bufio"
	"bytes"
	"github.com/kylelemons/go-gypsy/yaml"
	"io"
	"log"
	"path"
	"strconv"
)

// minimum total bad points to block a page
var blockThreshold int

// locations for files for built-in web server
var staticFilesDir, cgiBin string

var URLRules = newURLMatcher()

func loadConfiguration() {
	conf, err := yaml.ReadFile(*configFile)
	if err != nil {
		log.Print("Error reading config file: ", err)
		return
	}

	configDir, _ := path.Split(*configFile)

	s, _ := conf.Get("threshold")
	if s != "" {
		blockThreshold, err = strconv.Atoi(s)
		if err != nil {
			log.Print("Invalid value for threshold: ", s)
		}
	}

	blockPage, _ := conf.Get("blockpage")
	if blockPage == "" {
		blockPage = path.Join(configDir, "block.html")
	}
	loadBlockPageTemplate(blockPage)

	s, _ = conf.Get("staticfilesdir")
	if s == "" {
		s = path.Join(configDir, "static/")
	}
	staticFilesDir = s

	s, _ = conf.Get("cgibin")
	if s == "" {
		s = path.Join(configDir, "cgi")
	}
	cgiBin = s

	s, _ = conf.Get("categories")
	if s == "" {
		s = path.Join(configDir, "categories")
	}
	loadCategories(s)

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
