package main

import (
	"bytes"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// recording pages filtered to access log

var accessLogName = flag.String("access-log", "", "path to access-log file")

// logChan is a channel for sending context objects, once processing is
// completed, to be logged in the access log.
var logChan = make(chan []string)

// accessLog opens the log file and writes entries to it from logChan.
// It should be run in its own goroutine.
func accessLog() {
	var logfile = os.Stdout
	actualFile := false
	var err error
	var csvWriter *csv.Writer

	openLogFile := func() {
		if *accessLogName != "" {
			logfile, err = os.OpenFile(*accessLogName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
			if err != nil {
				log.Printf("Could not open access log file (%s): %s\n Sending access log messages to standard output instead.", *accessLogName, err)
				logfile = os.Stdout
				actualFile = false
			} else {
				actualFile = true
			}
		}
		csvWriter = csv.NewWriter(logfile)
	}
	openLogFile()

	hupChan := make(chan os.Signal, 1)
	signal.Notify(hupChan, syscall.SIGHUP)

	for {
		select {
		case c := <-logChan:
			csvWriter.Write(c)
			csvWriter.Flush()
		case <-hupChan:
			// When signaled with SIGHUP, close and reopen the log file.
			if actualFile {
				logfile.Close()
				openLogFile()
			}
		}
	}
}

// logAccess generates a log entry and sends it on logChan to be written.
func logAccess(req *http.Request, resp *http.Response, sc scorecard, contentType string, contentLength int, pruned bool, user string) {
	modified := ""
	if pruned {
		modified = "pruned"
	}

	if group := WhichGroup(user); group != "" {
		user = fmt.Sprintf("%s(%s)", user, group)
	}

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}

	logChan <- toStrings(time.Now().Format("2006-01-02 15:04:05"), user, sc.action, req.URL, req.Method, status, contentType, contentLength, modified, listTally(stringTally(sc.tally)), listTally(sc.scores), strings.Join(sc.blocked, ", "))
}

// toStrings converts its arguments into a slice of strings.
func toStrings(a ...interface{}) []string {
	result := make([]string, len(a))
	for i, x := range a {
		result[i] = fmt.Sprint(x)
	}
	return result
}

// stringTally returns a copy of tally with strings instead of rules as keys.
func stringTally(tally map[rule]int) map[string]int {
	st := make(map[string]int)
	for r, n := range tally {
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
