package main

// storage and loading of categories

import (
	"flag"
	"fmt"
	"github.com/kylelemons/go-gypsy/yaml"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var categoriesDir = flag.String("categories", "/etc/redwood/categories", "path to configuration files for categories")

// minimum bad points to block a page
var blockThreshold = flag.Int("threshold", 0, "minimum score for a blocked category to block a page")

var countOnce = flag.Bool("count-once", false, "count each phrase only once per page")

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

func (a action) String() string {
	switch a {
	case BLOCK:
		return "block"
	case IGNORE:
		return "ignore"
	case ALLOW:
		return "allow"
	}
	return "<invalid action>"
}

// A category represents one of the categories of filtering rules.
type category struct {
	name        string          // the directory name
	description string          // the name presented to users
	action      action          // the action to be taken with a page in this category
	weights     map[rule]weight // the weight for each rule
	invisible   bool            // use invisible GIF instead of block page
}

var categories = map[string]*category{
	"blocked-mime": &category{ // a fake category for pages blocked by MIME type
		name:        "blocked-mime",
		description: "Blocked MIME Type",
		action:      BLOCK,
	},
}

// loadCategories loads the category configuration files
func loadCategories() {
	dir, err := os.Open(*categoriesDir)
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
			categoryPath := filepath.Join(*categoriesDir, name)
			c, err := loadCategory(categoryPath)
			if err == nil {
				categories[c.name] = c
			} else {
				log.Printf("Error loading category %s: %v", name, err)
			}
		}
	}

	collectRules()
}

// loadCategory loads the configuration for one category
func loadCategory(dirname string) (c *category, err error) {
	c = new(category)
	c.weights = make(map[rule]weight)
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

	s, _ = conf.Get("invisible")
	if s != "" {
		c.invisible = true
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

			r, line, err := parseRule(line)
			if err != nil {
				log.Printf("Error in line %d of %s: %s", cr.LineNo, list, err)
				continue
			}

			var w weight
			n, _ := fmt.Sscan(line, &w.points, &w.maxPoints)
			if n == 0 {
				w.points = defaultWeight
			}

			if r.t == defaultRule {
				defaultWeight = w.points
			} else {
				c.weights[r] = w
			}
		}
	}

	return c, nil
}

// collectRules collects the rules from all the categories and adds
// them to URLRules and phraseRules.
func collectRules() {
	for _, c := range categories {
		for rule, _ := range c.weights {
			if rule.t == contentPhrase {
				addPhrase(rule)
			} else {
				URLRules.AddRule(rule)
			}
		}
	}
	findFallbackNodes(0, nil)
}

// score returns c's score for a page that matched
// the rules in tally. The keys are the rule names, and the values
// are the counts of how many times each rule was matched.
func (c *category) score(tally map[rule]int) int {
	total := 0
	weights := c.weights
	for r, count := range tally {
		w := weights[r]
		if *countOnce {
			total += w.points
			continue
		}
		p := w.points * count
		if w.maxPoints != 0 && (p > 0 && p > w.maxPoints || p < 0 && p < w.maxPoints) {
			p = w.maxPoints
		}
		total += p
	}
	return total
}

// categoryScores returns a map containing a page's score for each category.
func categoryScores(tally map[rule]int) map[string]int {
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
func blockedCategories(scores map[string]int, filterGroup string) []string {
	if len(scores) == 0 {
		return nil
	}

	blocked := make(map[string]int)
	maxAllowed := 0 // highest score of any category with action ALLOW
	for name, s := range scores {
		c := categories[name]
		if s > 0 {
			a := c.action
			if a1, ok := groupActions[filterGroup][name]; ok {
				a = a1
			}
			switch a {
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
				if s > maxAllowed && s > *blockThreshold {
					blocked[name] = s
				}
			}
		}
	}

	if len(blocked) == 0 {
		return nil
	}

	return sortedKeys(blocked)
}

// calculateScores calculates category scores and finds out whether the page
// needs to be blocked, based on c.tally.
func (c *context) calculateScores() {
	c.scores = categoryScores(c.tally)
	c.blocked = blockedCategories(c.scores, whichGroup[c.user()])
	if len(c.blocked) > 0 {
		c.action = BLOCK
	} else {
		c.action = ALLOW
	}
}
