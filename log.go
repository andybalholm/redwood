package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"time"
)

// recording pages filtered to access log

var accessLogChan = make(chan []string)
var tlsLogChan = make(chan []string)

type CSVLog struct {
	file *os.File
	csv  *csv.Writer
}

func NewCSVLog(filename string) *CSVLog {
	l := new(CSVLog)

	if filename != "" {
		logfile, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			log.Printf("Could not open log file (%s): %s\n Sending access log messages to standard output instead.", filename, err)
		} else {
			l.file = logfile
		}
	}
	if l.file == nil {
		l.file = os.Stdout
	}

	l.csv = csv.NewWriter(l.file)

	return l
}

func (l *CSVLog) Log(data []string) {
	l.csv.Write(data)
	l.csv.Flush()
}

func (l *CSVLog) Close() {
	if l.file == os.Stdout {
		return
	}
	l.file.Close()
}

func logAccess(req *http.Request, resp *http.Response, contentLength int, pruned bool, user string, tally map[rule]int, scores map[string]int, rule ACLActionRule) {
	modified := ""
	if pruned {
		modified = "pruned"
	}

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}

	if rule.Action == "" {
		rule.Action = "allow"
	}

	var contentType string
	if resp != nil {
		contentType = resp.Header.Get("Content-Type")
	}
	if ct2, _, err := mime.ParseMediaType(contentType); err == nil {
		contentType = ct2
	}

	accessLogChan <- toStrings(time.Now().Format("2006-01-02 15:04:05"), user, rule.Action, req.URL, req.Method, status, contentType, contentLength, modified, listTally(stringTally(tally)), listTally(scores), rule.Conditions())
}

func logTLS(user, serverAddr, serverName string, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}

	tlsLogChan <- toStrings(time.Now().Format("2006-01-02 15:04:05"), user, serverName, serverAddr, errStr)
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
