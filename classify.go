package main

import (
	"bytes"
	"encoding/json"
	"image"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/dhash"
	"github.com/klauspost/compress/gzip"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

type classificationResponse struct {
	URL        string         `json:"url,omitempty"`
	Text       string         `json:"text,omitempty"`
	Categories map[string]int `json:"categories,omitempty"`
	Error      string         `json:"error,omitempty"`
	LogLine    []string       `json:"logLine,omitempty"`
}

// handleClassification responds to an HTTP request with a url parameter, and
// responds with a JSON object describing how the page would be classified.
func handleClassification(w http.ResponseWriter, r *http.Request) {
	conf := getConfig()

	var result classificationResponse

	url := r.FormValue("url")
	result.URL = url
	if url == "" {
		http.Error(w, "The URL to classify must be supplied as an HTTP form parameter named 'url'.", 400)
		return
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.Error = err.Error()
		ServeJSON(w, r, result)
		log.Printf("Classifier: error creating request for %s: %v", url, err)
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		ServeJSON(w, r, result)
		log.Printf("Classifier: error fetching %s: %v", url, err)
		return
	}
	defer resp.Body.Close()

	// If the http Client followed redirects, use the final URL, not the one initially specified.
	req = resp.Request
	result.URL = req.URL.String()

	if resp.StatusCode != 200 {
		result.Error = resp.Status
		ServeJSON(w, r, result)
		log.Printf("Classifier: bad HTTP status fetching %s: %s", result.URL, resp.Status)
		return
	}

	reqACLs := conf.ACLs.requestACLs(req, "")
	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(reqACLs, respACLs)

	tally := conf.URLRules.MatchingRules(req.URL)
	scores := conf.categoryScores(tally)

	content, err := ioutil.ReadAll(&io.LimitedReader{
		R: resp.Body,
		N: 1 << 28,
	})
	if err != nil {
		result.Error = err.Error()
		ServeJSON(w, r, result)
		log.Printf("Classifier: error reading response body from %s: %v", result.URL, err)
		return
	}

	thisRule, _ := conf.ChooseACLCategoryAction(acls, scores, conf.Threshold, "allow", "block", "block-invisible", "hash-image", "phrase-scan")

	modified := false
	scoresNeedUpdate := false

	switch thisRule.Action {
	case "phrase-scan":
		contentType := resp.Header.Get("Content-Type")
		_, cs, _ := charset.DetermineEncoding(content, contentType)
		var doc *html.Node
		if strings.Contains(contentType, "html") {
			modified = conf.pruneContent(req.URL, &content, cs, &doc)
		}

		conf.scanContent(content, contentType, cs, tally)
		scoresNeedUpdate = true

	case "hash-image":
		img, _, err := image.Decode(bytes.NewReader(content))
		if err != nil {
			result.Error = resp.Status
			ServeJSON(w, r, result)
			log.Printf("Classifier: error decoding image from %v: %v", req.URL, err)
			return
		}
		hash := dhash.New(img)

		for _, h := range conf.ImageHashes {
			distance := dhash.Distance(hash, h.Hash)
			if distance <= h.Threshold || h.Threshold == -1 && distance <= conf.DhashThreshold {
				tally[rule{imageHash, h.String()}]++
				scoresNeedUpdate = true
			}
		}
	}

	if scoresNeedUpdate {
		scores = conf.categoryScores(tally)
	}

	for _, c := range conf.ClassifierIgnoredCategories {
		delete(scores, c)
	}
	for k, v := range scores {
		if v < conf.Threshold || conf.Categories[k].action == ACL {
			delete(scores, k)
		}
	}

	result.Categories = scores
	logLine := logAccess(req, resp, len(content), modified, "", tally, scores, ACLActionRule{Action: "classify"}, "", nil)
	if r.URL.Path == "/classify/verbose" {
		result.LogLine = logLine
	}
	ServeJSON(w, r, result)
}

// handleClassifyText is like handleClassify, but it takes the text to be
// classified from the "text" parameter instead of fetching a URL.
func handleClassifyText(w http.ResponseWriter, r *http.Request) {
	conf := getConfig()

	var result classificationResponse

	text := r.FormValue("text")
	result.Text = text
	if text == "" {
		http.Error(w, "The text to classify must be supplied as an HTTP form parameter named 'text'.", 400)
		return
	}

	tally := make(map[rule]int)
	conf.scanContent([]byte(text), "text/plain", "utf-8", tally)
	scores := conf.categoryScores(tally)

	for _, c := range conf.ClassifierIgnoredCategories {
		delete(scores, c)
	}
	result.Categories = scores

	ServeJSON(w, r, result)
}

// ServeJSON converts v to JSON and sends it on w.
func ServeJSON(w http.ResponseWriter, r *http.Request, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if len(data) > 1000 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gzw := gzip.NewWriter(w)
		defer gzw.Close()
		gzw.Write(data)
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Write(data)
	}
}
