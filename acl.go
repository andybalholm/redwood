package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Access Control Lists (ACLs)

// An ACLDefinitions object contains information about how to assign ACLs to a
// request.
type ACLDefinitions struct {
	ConnectPorts      map[int][]string
	ContentTypes      map[string][]string
	Methods           map[string][]string
	Referers          map[rule][]string
	RefererCategories map[string][]string
	StatusCodes       map[int][]string
	URLs              *URLMatcher
	URLTags           map[rule][]string
	UserIPs           IPMap
	UserNames         map[string][]string
	ServerIPs         IPMap
	JA3Fingerprints   map[string][]string

	// ExternalDeviceGroups is a cache of the device groups returned by the
	// authenticator-api endpoint.
	ExternalDeviceGroups map[string][]string
	ExternalDGLock       sync.RWMutex

	Times []struct {
		schedule WeeklySchedule
		acl      string
	}

	UserAgents []struct {
		regexp *regexp.Regexp
		acl    string
	}

	Descriptions map[string]string

	Actions []ACLActionRule
}

var errEmptyACLRule = errors.New("empty ACL rule")

// AddRule adds a rule to an ACL.
func (a *ACLDefinitions) AddRule(acl string, newRule []string) error {
	if len(newRule) == 0 {
		return errEmptyACLRule
	}

	keyword := newRule[0]
	args := newRule[1:]

	switch keyword {
	case "connect-port":
		if a.ConnectPorts == nil {
			a.ConnectPorts = make(map[int][]string)
		}
		for _, port := range args {
			p, err := strconv.Atoi(port)
			if err != nil {
				return err
			}
			a.ConnectPorts[p] = append(a.ConnectPorts[p], acl)
		}

	case "content-type":
		if a.ContentTypes == nil {
			a.ContentTypes = make(map[string][]string)
		}
		for _, ct := range args {
			a.ContentTypes[ct] = append(a.ContentTypes[ct], acl)
		}

	case "ja3":
		if a.JA3Fingerprints == nil {
			a.JA3Fingerprints = make(map[string][]string)
		}
		for _, ja3 := range args {
			a.JA3Fingerprints[ja3] = append(a.JA3Fingerprints[ja3], acl)
		}

	case "method":
		if a.Methods == nil {
			a.Methods = make(map[string][]string)
		}
		for _, m := range args {
			a.Methods[m] = append(a.Methods[m], acl)
		}

	case "referer", "referrer":
		if a.URLs == nil {
			a.URLs = newURLMatcher()
		}
		if a.Referers == nil {
			a.Referers = make(map[rule][]string)
		}
		for _, u := range args {
			u = strings.ToLower(u)
			r := simpleRule{t: urlMatch, content: u}
			a.URLs.AddRule(r)
			a.Referers[r] = append(a.Referers[r], acl)
		}

	case "referer-category", "referrer-category":
		if a.URLs == nil {
			// Initializing a.URLs shouldn't be necessary here,
			// but the rest of the referrer handling assumes it's initialized.
			a.URLs = newURLMatcher()
		}
		if a.RefererCategories == nil {
			a.RefererCategories = make(map[string][]string)
		}
		for _, rc := range args {
			a.RefererCategories[rc] = append(a.RefererCategories[rc], acl)
		}

	case "server-ip":
		for _, addr := range args {
			if err := a.ServerIPs.add(addr, acl); err != nil {
				return err
			}
		}

	case "http-status":
		if a.StatusCodes == nil {
			a.StatusCodes = make(map[int][]string)
		}
		for _, s := range args {
			status, err := strconv.Atoi(s)
			if err != nil {
				return fmt.Errorf("invalid HTTP status code: %q", s)
			}
			a.StatusCodes[status] = append(a.StatusCodes[status], acl)
		}

	case "time":
		s, err := ParseWeeklySchedule(args)
		if err != nil {
			return err
		}
		a.Times = append(a.Times, struct {
			schedule WeeklySchedule
			acl      string
		}{s, acl})

	case "url":
		if a.URLs == nil {
			a.URLs = newURLMatcher()
		}
		if a.URLTags == nil {
			a.URLTags = make(map[rule][]string)
		}
		for _, u := range args {
			u = strings.ToLower(u)
			r := simpleRule{t: urlMatch, content: u}
			a.URLs.AddRule(r)
			a.URLTags[r] = append(a.URLTags[r], acl)
		}

	case "user-agent":
		exp := strings.Join(args, " ")
		r, err := regexp.Compile("(?i)" + exp)
		if err != nil {
			return err
		}
		a.UserAgents = append(a.UserAgents, struct {
			regexp *regexp.Regexp
			acl    string
		}{r, acl})

	case "user-ip":
		for _, addr := range args {
			if err := a.UserIPs.add(addr, acl); err != nil {
				return err
			}
		}

	case "user-name":
		if a.UserNames == nil {
			a.UserNames = make(map[string][]string)
		}
		for _, name := range args {
			a.UserNames[name] = append(a.UserNames[name], acl)
		}

	default:
		return fmt.Errorf("unknown ACL rule keyword: %s", keyword)
	}

	return nil
}

// load loads ACL definitions and actions from a file.
func (a *ACLDefinitions) load(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		words := strings.Fields(line)
		for i, w := range words {
			if strings.HasPrefix(w, "#") {
				words = words[:i]
				break
			}
		}
		if len(words) == 0 {
			continue
		}
		action := words[0]
		args := words[1:]

		switch action {
		case "acl":
			// Define an ACL.
			if len(args) < 2 {
				log.Printf("Incomplete ACL definition at %s, line %d", filename, lineNo)
				continue
			}
			err = a.AddRule(args[0], args[1:])
			if err != nil {
				log.Printf("Error at %s, line %d: %v", filename, lineNo, err)
			}

		case "describe":
			// Give an acl a description for the block page.
			if len(args) < 2 {
				log.Printf("Incomplete ACL description at %s, line %d", filename, lineNo)
				continue
			}
			if a.Descriptions == nil {
				a.Descriptions = make(map[string]string)
			}
			a.Descriptions[args[0]] = strings.Join(args[1:], " ")

		case "include":
			for _, file := range args {
				if !filepath.IsAbs(file) {
					file = filepath.Join(filepath.Dir(filename), file)
				}
				err := a.load(file)
				if err != nil {
					log.Printf("Error including acl file %s: %v", file, err)
				}
			}

		case "allow", "block", "block-invisible", "censor-words", "disable-proxy-headers", "hash-image", "ignore-category", "log-content", "phrase-scan", "require-auth", "ssl-bump", "virus-scan":
			r := ACLActionRule{Action: action}
		argLoop:
			for _, a := range args {
				switch a[0] {
				case '!':
					r.Disallowed = append(r.Disallowed, a[1:])
				case '"':
					// Parse a description string.
					quoted := line[strings.Index(line, a):]
					_, err := fmt.Sscanf(quoted, "%q", &r.Description)
					if err != nil {
						log.Printf("Invalid quoted string at %s, line %d: %q", filename, lineNo, quoted)
					}
					break argLoop
				default:
					r.Needed = append(r.Needed, a)
					r.Bloom.Add(a)
				}
			}
			a.Actions = append(a.Actions, r)

		default:
			log.Printf("Invalid ACL action at %s, line %d: %s", filename, lineNo, action)
		}
	}

	return scanner.Err()
}

// requestACLs returns the set of ACLs that apply to r.
func (a *ACLDefinitions) requestACLs(r *http.Request, user string) map[string]bool {
	acls := make(map[string]bool)

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			for _, a := range a.UserIPs.matches(ip) {
				acls[a] = true
			}
		}
	}

	if user != "" {
		for _, a := range a.UserNames[user] {
			acls[a] = true
		}
		a.ExternalDGLock.RLock()
		groups := a.ExternalDeviceGroups[user]
		a.ExternalDGLock.RUnlock()
		for _, a := range groups {
			acls[a] = true
		}
	}

	for _, a := range a.Methods[r.Method] {
		acls[a] = true
	}

	if r.Method == "CONNECT" {
		_, port, err := net.SplitHostPort(r.Host)
		if err != nil {
			port = "443"
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			p = 443
		}
		for _, a := range a.ConnectPorts[p] {
			acls[a] = true
		}
	}

	now := time.Now()
	day := now.Weekday()
	h, m, _ := now.Clock()
	for _, t := range a.Times {
		if t.schedule.Contains(day, h, m) {
			acls[t.acl] = true
		}
	}

	if a.URLs != nil {
		for match := range a.URLs.MatchingRules(r.URL) {
			for _, acl := range a.URLTags[match] {
				acls[acl] = true
			}
		}

		if referer := r.Header.Get("Referer"); referer != "" {
			refURL, err := url.Parse(referer)
			if err == nil {
				for match := range a.URLs.MatchingRules(refURL) {
					for _, acl := range a.Referers[match] {
						acls[acl] = true
					}
				}

				if a.RefererCategories != nil {
					conf := getConfig()
					tally := conf.URLRules.MatchingRules(refURL)
					scores := conf.categoryScores(tally)
					for c, score := range scores {
						if score <= 0 {
							continue
						}
						for _, acl := range a.RefererCategories[c] {
							acls[acl] = true
						}
					}
				}
			}
		}
	}

	server := r.URL.Host
	if host, _, err := net.SplitHostPort(server); err == nil {
		server = host
	}
	if ip := net.ParseIP(server); ip != nil {
		for _, acl := range a.ServerIPs.matches(ip) {
			acls[acl] = true
		}
	}

	if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
		for _, u := range a.UserAgents {
			if u.regexp.MatchString(userAgent) {
				acls[u.acl] = true
			}
		}
	}

	if tlsFingerprint, ok := r.Context().Value(tlsFingerprintKey{}).(string); ok {
		for _, acl := range a.JA3Fingerprints[tlsFingerprint] {
			acls[acl] = true
		}
	}

	return acls
}

// responseACLs returns the set of ACLs that apply to resp.
func (a *ACLDefinitions) responseACLs(resp *http.Response) map[string]bool {
	acls := make(map[string]bool)

	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch ct {
	case "unknown/unknown", "application/unknown", "*/*", "":
		// These types tend to be used for content whose type is unknown,
		// so we should try to second-guess them.
		preview := make([]byte, 512)
		n, _ := resp.Body.Read(preview)
		preview = preview[:n]

		if n > 0 {
			ct, _, _ = mime.ParseMediaType(http.DetectContentType(preview))
			log.Printf("Detected Content-Type as %q for %v", ct, resp.Request.URL)
			if resp.Header["Content-Type"] == nil {
				resp.Header.Set("Content-Type", ct)
			}

			// Make the preview data available for re-reading.
			var rc struct {
				io.Reader
				io.Closer
			}
			rc.Reader = io.MultiReader(bytes.NewReader(preview), resp.Body)
			rc.Closer = resp.Body
			resp.Body = rc
		}
	}
	for _, acl := range a.ContentTypes[ct] {
		acls[acl] = true
	}
	slash := strings.Index(ct, "/")
	if slash != -1 {
		generic := ct[:slash+1] + "*"
		for _, acl := range a.ContentTypes[generic] {
			acls[acl] = true
		}
	}

	status := resp.StatusCode
	for _, acl := range a.StatusCodes[status] {
		acls[acl] = true
	}
	// Also include the general status code category (multiple of 100).
	status = status / 100 * 100
	for _, acl := range a.StatusCodes[status] {
		acls[acl] = true
	}

	return acls
}

// An ACLActionRule specifies an action that will be performed if a request
// belongs to a certain set of ACLs.
type ACLActionRule struct {
	// Action is the name of the action that will be taken.
	Action string

	// Needed is a list of ACLs that the request must belong to.
	Needed []string

	// Disallowed is a list of ACLs that the request must not belong to.
	Disallowed []string

	// Description is an explanation of why the action was chosen, suitable for
	// display to end users.
	Description string

	// Bloom is a bloomFilter containing the Needed ACLs.
	Bloom bloomFilter `json:"-"`
}

// Conditions returns a string summarizing r's conditions.
func (r ACLActionRule) Conditions() string {
	var desc []string
	for _, a := range r.Needed {
		desc = append(desc, a)
	}
	for _, a := range r.Disallowed {
		desc = append(desc, "!"+a)
	}
	return strings.Join(desc, " ")
}

// ChooseACLAction returns the first ACL action rule that
// matches acls and has an action in actions. If no rule matches, it returns
// a blank rule.
func (a *ACLDefinitions) ChooseACLAction(acls map[string]bool, actions ...string) ACLActionRule {
	choices := make(map[string]bool, len(actions))
	for _, a := range actions {
		choices[a] = true
	}

	var bloom bloomFilter
	for a := range acls {
		bloom.Add(a)
	}

ruleLoop:
	for _, r := range a.Actions {
		if !bloom.Superset(&r.Bloom) {
			continue ruleLoop
		}

		if !choices[r.Action] {
			continue ruleLoop
		}

		for _, a := range r.Needed {
			if !acls[a] {
				continue ruleLoop
			}
		}
		for _, a := range r.Disallowed {
			if acls[a] {
				continue ruleLoop
			}
		}
		return r
	}

	return ACLActionRule{}
}

func copyACLSet(a map[string]bool) map[string]bool {
	b := make(map[string]bool)
	for k, v := range a {
		if v {
			b[k] = true
		}
	}
	return b
}

func unionACLSets(sets ...map[string]bool) map[string]bool {
	b := make(map[string]bool)
	for _, a := range sets {
		for k, v := range a {
			if v {
				b[k] = true
			}
		}
	}
	return b
}

// ChooseACLCategoryAction is like ChooseACLAction, except that it also takes
// a tally of category scores. Any ACL categories (action==ACL) with positive
// scores are added to the set of ACLs. A list is made of all the other
// categories with scores over the threshold, with the highest-scoring category
// first. The first category in the list is added to the set of
// ACLs. If the result is empty, the default action for that category will be
// used. Then if the result is "ignore-category", the process will be repeated
// with the next category in the list. Finally, if all categories are ignored,
// the process is repeated with just the original set of ACLs and ACL
// categories. The second return value is a list of the categories that were
// ignored.
func (c *config) ChooseACLCategoryAction(acls map[string]bool, scores map[string]int, threshold int, actions ...string) (ar ACLActionRule, ignored []string) {
	choices := make(map[string]bool, len(actions))
	for _, a := range actions {
		choices[a] = true
	}

	acls = copyACLSet(acls)
	significantScores := make(map[string]int)
	for k, v := range scores {
		if v > 0 && c.Categories[k] != nil && c.Categories[k].action == ACL {
			acls[k] = true
			continue
		}
		if v >= threshold {
			significantScores[k] = v
		}
	}
	categories := sortedKeys(significantScores)

	var masterBloom bloomFilter
	for a := range acls {
		masterBloom.Add(a)
	}

	for _, cat := range categories {
		bloom := masterBloom
		bloom.Add(cat)
		var r ACLActionRule
		found := false

	ruleLoop:
		for _, r = range c.ACLs.Actions {
			if !bloom.Superset(&r.Bloom) {
				continue ruleLoop
			}

			okToIgnore := false
			for _, a := range r.Needed {
				if !acls[a] && a != cat {
					continue ruleLoop
				}
				if a == cat {
					// We should honor an ignore-category rule only if the category to be ignored
					// is one of the conditions for the rule.
					okToIgnore = true
				}
			}
			for _, a := range r.Disallowed {
				if acls[a] || a == cat {
					continue ruleLoop
				}
			}

			if choices[r.Action] {
				found = true
			}
			if okToIgnore && r.Action == "ignore-category" {
				found = true
			}

			if found {
				break ruleLoop
			}
		}

		if !found {
			cg := c.Categories[cat]
			r = ACLActionRule{
				Needed: []string{cat},
			}
			if cg != nil {
				switch cg.action {
				case BLOCK:
					if cg.invisible && choices["block-invisible"] {
						r.Action = "block-invisible"
					} else if choices["block"] {
						r.Action = "block"
					}
				case IGNORE:
					r.Action = "ignore-category"
				case ALLOW:
					if choices["allow"] {
						r.Action = "allow"
					}
				}
			}
		}
		if r.Action == "ignore-category" || r.Action == "" {
			ignored = append(ignored, cat)
		} else {
			return r, ignored
		}
	}

	return c.ACLs.ChooseACLAction(acls, actions...), ignored
}
