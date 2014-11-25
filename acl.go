package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Access Control Lists (ACLs)

// An ACLDefinitions object contains information about how to assign ACLs to a
// request.
type ACLDefinitions struct {
	ContentTypes    map[string][]string
	Methods         map[string][]string
	Referers        map[string][]string
	URLs            *URLMatcher
	URLTags         map[string][]string
	UserIPAddresses map[string][]string
	UserIPRanges    []rangeToGroup
	UserNames       map[string][]string

	Times []struct {
		schedule WeeklySchedule
		acl      string
	}

	Descriptions map[string]string
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
	case "content-type":
		if a.ContentTypes == nil {
			a.ContentTypes = make(map[string][]string)
		}
		for _, ct := range args {
			a.ContentTypes[ct] = append(a.ContentTypes[ct], acl)
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
			a.Referers = make(map[string][]string)
		}
		for _, u := range args {
			u = strings.ToLower(u)
			a.URLs.AddRule(rule{t: urlMatch, content: u})
			a.Referers[u] = append(a.Referers[u], acl)
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
			a.URLTags = make(map[string][]string)
		}
		for _, u := range args {
			u = strings.ToLower(u)
			a.URLs.AddRule(rule{t: urlMatch, content: u})
			a.URLTags[u] = append(a.URLTags[u], acl)
		}

	case "user-ip":
		if a.UserIPAddresses == nil {
			a.UserIPAddresses = make(map[string][]string)
		}
		for _, addr := range args {
			if ip := net.ParseIP(addr); ip != nil {
				s := ip.String()
				a.UserIPAddresses[s] = append(a.UserIPAddresses[s], acl)
				continue
			}
			r, err := ParseIPRange(addr)
			if err != nil {
				return fmt.Errorf("invalid IP address or range: %s", addr)
			}
			a.UserIPRanges = append(a.UserIPRanges, rangeToGroup{r, acl})
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

// loadACLs loads ACL definitions and actions from a file.
func (c *config) loadACLs(filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	c.ACLsLoaded = true

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
			err = c.ACLs.AddRule(args[0], args[1:])
			if err != nil {
				log.Printf("Error at %s, line %d: %v", filename, lineNo, err)
			}

		case "describe":
			// Give an acl a description for the block page.
			if len(args) < 2 {
				log.Printf("Incomplete ACL description at %s, line %d", filename, lineNo)
				continue
			}
			if c.ACLs.Descriptions == nil {
				c.ACLs.Descriptions = make(map[string]string)
			}
			c.ACLs.Descriptions[args[0]] = strings.Join(args[1:], " ")

		case "include":
			for _, file := range args {
				if !filepath.IsAbs(file) {
					file = filepath.Join(filepath.Dir(filename), file)
				}
				err = c.loadACLs(file)
				if err != nil {
					log.Printf("Error including acl file %s: %v", file, err)
				}
			}

		case "allow", "block", "block-invisible", "ignore-category", "phrase-scan", "require-auth", "ssl-bump":
			r := ACLActionRule{Action: action}
			for _, a := range args {
				if strings.HasPrefix(a, "!") {
					r.Disallowed = append(r.Disallowed, a[1:])
				} else {
					r.Needed = append(r.Needed, a)
				}
			}
			c.ACLActions = append(c.ACLActions, r)

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
			for _, a := range a.UserIPAddresses[ip.String()] {
				acls[a] = true
			}
			for _, r := range a.UserIPRanges {
				if r.r.Contains(ip) {
					acls[r.group] = true
				}
			}
		}
	}

	if user != "" {
		for _, a := range a.UserNames[user] {
			acls[a] = true
		}
	}

	for _, a := range a.Methods[r.Method] {
		acls[a] = true
	}

	now := time.Now()
	for _, t := range a.Times {
		if t.schedule.Contains(now) {
			acls[t.acl] = true
		}
	}

	if a.URLs != nil {
		for match := range a.URLs.MatchingRules(r.URL) {
			for _, acl := range a.URLTags[match.content] {
				acls[acl] = true
			}
		}

		if referer := r.Header.Get("Referer"); referer != "" {
			refURL, err := url.Parse(referer)
			if err == nil {
				for match := range a.URLs.MatchingRules(refURL) {
					for _, acl := range a.Referers[match.content] {
						acls[acl] = true
					}
				}
			}
		}
	}

	return acls
}

// responseACLs returns the set of ACLs that apply to resp.
func (a *ACLDefinitions) responseACLs(resp *http.Response) map[string]bool {
	acls := make(map[string]bool)

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if ct2, _, err := mime.ParseMediaType(ct); err == nil {
			ct = ct2
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
func (c *config) ChooseACLAction(acls map[string]bool, actions ...string) ACLActionRule {
	choices := make(map[string]bool, len(actions))
	for _, a := range actions {
		choices[a] = true
	}

ruleLoop:
	for _, r := range c.ACLActions {
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
// a list of categories. The first category in the list is added to the set of
// ACLs. If the result is empty, the default action for that category will be
// used. Then if the result is "ignore-category", the process will be repeated
// with the next category in the list. Finally, if all categories are ignored,
// the process is repeated with just the original set of ACLs.
func (c *config) ChooseACLCategoryAction(acls map[string]bool, categories []string, actions ...string) ACLActionRule {
	actionsPlus := append(actions, "ignore-category")
	choices := make(map[string]bool, len(actions))
	for _, a := range actions {
		choices[a] = true
	}

	for _, cat := range categories {
		aclsPlus := copyACLSet(acls)
		aclsPlus[cat] = true
		r := c.ChooseACLAction(aclsPlus, actionsPlus...)
		if r.Action == "" {
			cg := c.Categories[cat]
			r.Needed = []string{cat}
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
		if r.Action != "ignore-category" {
			return r
		}
	}

	return c.ChooseACLAction(acls, actions...)
}
