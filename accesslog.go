package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"
)

// recording pages filtered to access log

var accessLogName = flag.String("access-log", "", "path to access-log file")

// logChan is a channel for sending context objects, once processing is
// completed, to be logged in the access log.
var logChan = make(chan *context, 10)

// When a value is sent on logResetChan, the log file will be closed and
// reopened (for compatibility with logrotate).
var logResetChan = make(chan bool, 1)

// accessLog opens the log file and writes entries to it from logChan.
// It should be run in its own goroutine.
func accessLog() {
	var logfile = os.Stdout
	actualFile := false
	var err error
	if *accessLogName != "" {
		logfile, err = os.OpenFile(*accessLogName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Printf("Could not open access log file (%s): %s\n Sending access log messages to standard output instead.", *accessLogName, err)
			logfile = os.Stdout
		} else {
			actualFile = true
		}
	}

	i := 0 // a count of transactions logged

	for {
		select {
		case c := <-logChan:
			c.log(logfile)
			i++
			if i%100 == 0 {
				runtime.GC()
			}
		case <-logResetChan:
			if actualFile {
				logfile.Close()
				logfile, err = os.OpenFile(*accessLogName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
				if err != nil {
					log.Printf("Could not open access log file (%s): %s\n Sending access log messages to standard output instead.", *accessLogName, err)
					logfile = os.Stdout
					actualFile = false
				}
			}
		}
	}
}

// log writes a log entry (in CSV format) to w.
func (c *context) log(w io.Writer) {
	mode := c.req.Method

	modified := ""
	if c.modified {
		modified = "pruned"
	}

	user := c.user()
	if group := whichGroup[user]; group != "" {
		user = fmt.Sprintf("%s(%s)", user, group)
	}

	fmt.Fprintf(w, "%q,%q,%q,%q,%q,%q,%d,%q,%q,%q,%q\n", time.Now().Format("2006-01-02 15:04:05"), user, c.action, c.URL(), mode, c.mime, len(c.content), modified, listTally(c.stringTally()), listTally(c.scores), strings.Join(c.blocked, ", "))
}

// stringTally returns a copy of c.tally with strings instead of rules as keys.
func (c *context) stringTally() map[string]int {
	st := make(map[string]int)
	for r, n := range c.tally {
		st[r.String()] = n
	}
	return st
}

// listTally sorts the tally and formats it as a comma-separated string.
func listTally(tally map[string]int) string {
	b := new(bytes.Buffer)
	for i, rule := range sortedKeys(tally) {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprint(b, rule, " ", tally[rule])
	}
	return b.String()
}
