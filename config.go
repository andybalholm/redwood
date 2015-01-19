package main

// functions for reading configuration files

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"code.google.com/p/cascadia"
)

// A config object holds a complete set of Redwood's configuration settings.
type config struct {
	BlockTemplate     *template.Template
	Categories        map[string]*category
	ContentPhraseList phraseList
	CountOnce         bool
	DisableGZIP       bool
	Threshold         int
	URLRules          *URLMatcher

	ACLs       ACLDefinitions
	ACLActions []ACLActionRule
	ACLsLoaded bool

	PIDFile string
	TestURL string

	ProxyAddresses       []string
	TransparentAddresses []string

	CGIBin         string
	ServeMux       *http.ServeMux
	StaticFilesDir string
	VirtualHosts   map[string]string

	PruneActions    map[rule]cascadia.Selector
	FilteredPruning map[rule][]filteredPruningRule
	PruneMatcher    *URLMatcher
	QueryChanges    map[rule]url.Values
	QueryMatcher    *URLMatcher

	CertFile       string
	KeyFile        string
	TLSCert        tls.Certificate
	ParsedTLSCert  *x509.Certificate
	TLSReady       bool
	ExtraRootCerts *x509.CertPool

	Authenticators []func(user, password string) bool
	Passwords      map[string]string
	PasswordLock   sync.RWMutex

	AccessLog string
	TLSLog    string

	flags *flag.FlagSet
}

func loadConfiguration() (*config, error) {
	c := &config{
		flags:             flag.NewFlagSet("config", flag.ContinueOnError),
		URLRules:          newURLMatcher(),
		PruneActions:      map[rule]cascadia.Selector{},
		FilteredPruning:   map[rule][]filteredPruningRule{},
		PruneMatcher:      newURLMatcher(),
		QueryChanges:      map[rule]url.Values{},
		QueryMatcher:      newURLMatcher(),
		VirtualHosts:      map[string]string{},
		ServeMux:          http.NewServeMux(),
		ContentPhraseList: newPhraseList(),
		Passwords:         map[string]string{},
	}

	c.flags.StringVar(&c.AccessLog, "access-log", "", "path to access-log file")
	c.newActiveFlag("acls", "", "access-control-list (ACL) rule file", c.loadACLs)
	c.newActiveFlag("auth-helper", "", "program to authenticate users", c.startAuthHelper)
	c.newActiveFlag("blockpage", "", "path to template for block page", c.loadBlockPage)
	c.newActiveFlag("c", "/etc/redwood/redwood.conf", "configuration file path", c.readConfigFile)
	c.newActiveFlag("categories", "/etc/redwood/categories", "path to configuration files for categories", c.loadCategories)
	c.flags.StringVar(&c.CGIBin, "cgi-bin", "", "path to CGI files for built-in web server")
	c.newActiveFlag("content-pruning", "", "path to config file for content pruning", c.loadPruningConfig)
	c.flags.BoolVar(&c.CountOnce, "count-once", false, "count each phrase only once per page")
	c.flags.BoolVar(&c.DisableGZIP, "disable-gzip", false, "Don't compress HTTP responses with gzip.")
	c.newActiveFlag("include", "", "additional config file to read", c.readConfigFile)
	c.newActiveFlag("password-file", "", "path to file of usernames and passwords", c.readPasswordFile)
	c.flags.StringVar(&c.PIDFile, "pidfile", "", "path of file to store process ID")
	c.newActiveFlag("query-changes", "", "path to config file for modifying URL query strings", c.loadQueryConfig)
	c.flags.StringVar(&c.StaticFilesDir, "static-files-dir", "", "path to static files for built-in web server")
	c.flags.StringVar(&c.TestURL, "test", "", "URL to test instead of running proxy server")
	c.flags.IntVar(&c.Threshold, "threshold", 0, "minimum score for a blocked category to block a page")
	c.flags.StringVar(&c.CertFile, "tls-cert", "", "path to certificate for serving HTTPS")
	c.flags.StringVar(&c.KeyFile, "tls-key", "", "path to TLS certificate key")
	c.flags.StringVar(&c.TLSLog, "tls-log", "", "path to tls log file")
	c.newActiveFlag("trusted-root", "", "path to file of additional trusted root certificates (in PEM format)", c.addTrustedRoots)

	c.newActiveFlag("http-proxy", "", "address (host:port) to listen for proxy connections on", func(s string) error {
		c.ProxyAddresses = append(c.ProxyAddresses, s)
		return nil
	})
	c.newActiveFlag("transparent-https", "", "address to listen for intercepted HTTPS connections on", func(s string) error {
		c.TransparentAddresses = append(c.TransparentAddresses, s)
		return nil
	})

	c.newActiveFlag("virtual-host", "", "a hostname substitution to apply to HTTP requests (e.g. -virtual-host me.local localhost)", func(val string) error {
		f := strings.Fields(val)
		if len(f) != 2 {
			return errors.New("the virtual-host option takes two hostnames (with optional ports), separated by a space: fake.name real.name")
		}
		c.VirtualHosts[f[0]] = f[1]
		return nil
	})

	// Read the default configuration file if none is specified with -c
	specified := false
	for _, arg := range os.Args {
		if arg == "-c" || arg == "--c" {
			specified = true
			break
		}
	}
	if !specified {
		err := c.readConfigFile("/etc/redwood/redwood.conf")
		if err != nil {
			return nil, err
		}
	}

	err := c.flags.Parse(os.Args[1:])
	if err != nil {
		return nil, err
	}

	if c.Categories == nil {
		err := c.loadCategories("/etc/redwood/categories")
		if err != nil {
			log.Println(err)
		}
	}
	c.collectRules()

	c.loadCertificate()

	return c, nil
}

// readConfigFile reads the specified configuration file.
// For each line of the form "key value" or "key = value", it sets the flag
// variable named key to a value of value.
func (c *config) readConfigFile(filename string) error {
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

		err = c.flags.Set(key, value)
		if err != nil {
			log.Println("Could not set", key, "to", value, ":", err)
		}
	}

	return nil
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

func (c *config) newActiveFlag(name, value, usage string, f func(string) error) flag.Value {
	af := &activeFlag{
		f:     f,
		value: value,
	}
	c.flags.Var(af, name, usage)
	return af
}
