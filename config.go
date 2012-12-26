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
	"strings"
)

var configFile = newActiveFlag("c", "/etc/redwood/redwood.conf", "configuration file path", readConfigFile)

var URLRules = newURLMatcher()

// readConfigFile reads the specified configuration file.
// For each line of the form "key value" or "key = value", it sets the flag
// variable named key to a value of value.
func readConfigFile(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("could not open %s: %s", filename, err)
	}
	defer f.Close()
	r := bufio.NewReader(f)

	for {
		line, err := r.ReadString('\n')
		if line == "" {
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

	return nil
}

func loadConfiguration() {
	// Read the default configuration file if none is specified with -c
	specified := false
	for _, arg := range os.Args {
		if arg == "-c" || arg == "--c" {
			specified = true
			break
		}
	}
	if !specified {
		err := readConfigFile("/etc/redwood/redwood.conf")
		if err != nil {
			log.Println(err)
		}
	}

	flag.Parse()

	loadBlockPage()
	loadCategories()
	loadCertificate()
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

// an activeFlag runs a function when the flag's value is set.
type activeFlag struct {
	f     func(string) error
	value string
}

func (af *activeFlag) String() string {
	return af.value
}

func (af *activeFlag) Set(s string) error {
	err := af.f(s)
	if err == nil {
		af.value = s
	}
	return err
}

func newActiveFlag(name, value, usage string, f func(string) error) flag.Value {
	af := &activeFlag{
		f:     f,
		value: value,
	}
	flag.Var(af, name, usage)
	return af
}
