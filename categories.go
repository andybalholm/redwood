package main

// storage and loading of categories

import (
	"fmt"
	"github.com/kylelemons/go-gypsy/yaml"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// A weight contains the point values assigned to a rule+category combination.
type weight struct {
	points    int // points per occurrence
	maxPoints int // maximum points per page
}

// An action is the action assigned to a category.
type action int

const (
	BLOCK  action = -1
	IGNORE action = 0
	ALLOW  action = 1
)

// A category represents one of the categories of filtering rules.
type category struct {
	name        string            // the directory name
	description string            // the name presented to users
	action      action            // the action to be taken with a page in this category
	weights     map[string]weight // the weight for each rule; the key is the canonical form of the rule
}

var categories []*category
var categoryDescriptions = make(map[string]string) // Maps names to descriptions.

// loadCategories loads the category configuration files
func loadCategories(dirname string) {
	dir, err := os.Open(dirname)
	if err != nil {
		log.Print("Could not open category directory: ", err)
		return
	}
	defer dir.Close()

	info, err := dir.Readdir(0)
	if err != nil {
		log.Print("Could not read category directory: ", err)
		return
	}

	for _, fi := range info {
		if name := fi.Name(); fi.IsDir() && name[0] != '.' {
			categoryPath := filepath.Join(dirname, name)
			c, err := loadCategory(categoryPath)
			if err == nil {
				categories = append(categories, c)
				categoryDescriptions[c.name] = c.description
			} else {
				log.Printf("Error loading category %s: %v", name, err)
			}
		}
	}
}

// loadCategory loads the configuration for one category
func loadCategory(dirname string) (c *category, err error) {
	c = new(category)
	c.weights = make(map[string]weight)
	c.name = filepath.Base(dirname)
	c.description = c.name

	confFile := filepath.Join(dirname, "category.conf")
	conf, err := yaml.ReadFile(confFile)
	if err != nil {
		return nil, err
	}
	s, _ := conf.Get("description")
	if s != "" {
		c.description = s
	}

	s, _ = conf.Get("action")
	s = strings.ToLower(s)
	switch s {
	case "allow":
		c.action = ALLOW
	case "ignore":
		c.action = IGNORE
	case "block":
		c.action = BLOCK
	case "":
		// No-op.
	default:
		return nil, fmt.Errorf("unrecognized action %s in %s", s, confFile)
	}

	ruleFiles, err := filepath.Glob(filepath.Join(dirname, "*.list"))
	if err != nil {
		return nil, fmt.Errorf("error listing rule files: %v", err)
	}
	for _, list := range ruleFiles {
		r, err := os.Open(list)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		cr := newConfigReader(r)

		defaultWeight := 0

		for {
			line, err := cr.ReadLine()
			if err != nil {
				break
			}

			var rule string

			switch line[0] {
			case '/':
				// regular expression
				slash := strings.LastIndex(line, "/")
				if slash == 0 {
					log.Printf("Unmatched slash in line %d of %s", cr.LineNo, list)
					continue
				}
				rule = line[:slash+1]
				if len(line) > slash+1 {
					if c := line[slash+1]; c == 'h' || c == 'p' || c == 'q' {
						rule = line[:slash+2]
					}
				}
			case '<':
				// content phrase
				bracket := strings.LastIndex(line, ">")
				if bracket == -1 {
					log.Printf("Unmatched '<' in line %d of %s", cr.LineNo, list)
					continue
				}
				rule = line[:bracket+1]
			default:
				// URL match
				space := strings.Index(line, " ")
				if space == -1 {
					rule = line
				} else {
					rule = line[:space]
				}
			}

			line = line[len(rule):]
			if rule[0] == '<' {
				rule = "<" + wordString(rule[1:len(rule)-1]) + ">"
			} else {
				rule = strings.ToLower(rule)
			}

			var w weight
			n, _ := fmt.Sscan(line, &w.points, &w.maxPoints)
			if n == 0 {
				w.points = defaultWeight
			}

			if rule == "default" {
				defaultWeight = w.points
			} else {
				c.weights[rule] = w
			}
		}
	}

	return c, nil
}

// score returns c's score for a page that matched
// the rules in tally. The keys are the rule names, and the values
// are the counts of how many times each rule was matched.
func (c *category) score(tally map[string]int) int {
	total := 0
	weights := c.weights
	for rule, count := range tally {
		w := weights[rule]
		p := w.points * count
		if w.maxPoints != 0 && (p > 0 && p > w.maxPoints || p < 0 && p < w.maxPoints) {
			p = w.maxPoints
		}
		total += p
	}
	return total
}

// categoryScores returns a map containing a page's score for each category.
func categoryScores(tally map[string]int) map[string]int {
	if len(tally) == 0 {
		return nil
	}

	scores := make(map[string]int)
	for _, c := range categories {
		s := c.score(tally)
		if s != 0 {
			scores[c.name] = s
		}
	}
	return scores
}

// blockedCategories returns a list of categories that would cause a page to be blocked.
// The keys of scores are category names, and the values are the number of points scored.
func blockedCategories(scores map[string]int) []string {
	if len(scores) == 0 {
		return nil
	}

	blocked := make(map[string]int)
	maxAllowed := 0   // highest score of any category with action ALLOW
	totalBlocked := 0 // total score of all categories with action BLOCK
	for _, c := range categories {
		s := scores[c.name]
		if s > 0 {
			switch c.action {
			case ALLOW:
				if s > maxAllowed {
					maxAllowed = s

					// If any categories on the blocked list have lower scores, remove them.
					for bn, bs := range blocked {
						if bs <= s {
							delete(blocked, bn)
						}
					}
				}

			case BLOCK:
				totalBlocked += s
				if s > maxAllowed {
					blocked[c.name] = s
				}
			}
		}
	}

	if totalBlocked < blockThreshold || len(blocked) == 0 {
		return nil
	}

	return sortedKeys(blocked)
}

// calculateScores calculates category scores and finds out whether the page
// needs to be blocked, based on c.tally.
func (c *context) calculateScores() {
	c.scores = categoryScores(c.tally)
	c.blocked = blockedCategories(c.scores)
	if len(c.blocked) > 0 {
		c.action = BLOCK
	} else {
		c.action = ALLOW
	}
}
