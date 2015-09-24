package main

import (
	"bytes"
	"encoding/json"
	"image"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/dhash"
	"github.com/klauspost/compress/gzip"
	"golang.org/x/net/html/charset"
)

type classificationResponse struct {
	URL        string         `json:"url"`
	Categories map[string]int `json:"categories,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// handleClassification responds to an HTTP request with a url parameter, and
// responds with a JSON object describing how the page would be classified.
func handleClassification(w http.ResponseWriter, r *http.Request) {
	activeConnections.Add(1)
	defer activeConnections.Done()

	conf := getConfig()

	var result classificationResponse

	result.URL = r.FormValue("url")
	if result.URL == "" {
		http.Error(w, "The URL to classify must be supplied as an HTTP form parameter named 'url'.", 400)
		return
	}

	req, err := http.NewRequest("GET", result.URL, nil)
	if err != nil {
		result.Error = err.Error()
		ServeJSON(w, r, result)
		log.Printf("Classifier: error creating HTTP request for %s: %v", result.URL, err)
		return
	}

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		result.Error = err.Error()
		ServeJSON(w, r, result)
		log.Printf("Classifier: error fetching %s: %v", result.URL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		result.Error = resp.Status
		ServeJSON(w, r, result)
		log.Printf("Classifier: bad HTTP status fetching %s: %s", result.URL, resp.Status)
		return
	}

	fixContentType(resp)

	reqACLs := conf.ACLs.requestACLs(req, "")
	respACLs := conf.ACLs.responseACLs(resp)
	acls := unionACLSets(reqACLs, respACLs)

	tally := conf.URLRules.MatchingRules(req.URL)
	scores := conf.categoryScores(tally)
	categories := conf.significantCategories(scores)

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.Error = err.Error()
		ServeJSON(w, r, result)
		log.Printf("Classifier: error reading response body from %s: %v", result.URL, err)
		return
	}

	thisRule, _ := conf.ChooseACLCategoryAction(acls, categories, "allow", "block", "block-invisible", "hash-image", "phrase-scan")

	modified := false
	scoresNeedUpdate := false

	switch thisRule.Action {
	case "phrase-scan":
		contentType := resp.Header.Get("Content-Type")
		_, cs, _ := charset.DetermineEncoding(content, contentType)
		if strings.Contains(contentType, "html") {
			modified = conf.pruneContent(req.URL, &content, cs, acls, nil)
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
		categories = conf.significantCategories(scores)
	}

	for _, c := range conf.ClassifierIgnoredCategories {
		delete(scores, c)
	}
	for k, v := range scores {
		if v < conf.Threshold {
			delete(scores, k)
		}
	}

	result.Categories = scores
	ServeJSON(w, r, result)
	logAccess(req, resp, len(content), modified, "", tally, scores, ACLActionRule{Action: "classify"}, "", nil, "")
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
