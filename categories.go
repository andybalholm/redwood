package main

// storage and loading of categories

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/andybalholm/dhash"
	"github.com/kylelemons/go-gypsy/yaml"
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
	ACL    action = 2
)

func (a action) String() string {
	switch a {
	case BLOCK:
		return "block"
	case IGNORE:
		return "ignore"
	case ALLOW:
		return "allow"
	case ACL:
		return "acl"
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

// loadCategories loads the category configuration files
func (cf *config) loadCategories(dirName string) error {
	if cf.Categories == nil {
		cf.Categories = map[string]*category{}
	}

	dir, err := os.Open(dirName)
	if err != nil {
		return fmt.Errorf("Could not open category directory: %v", err)
	}
	defer dir.Close()

	info, err := dir.Readdir(0)
	if err != nil {
		return fmt.Errorf("Could not read category directory: %v", err)
	}

	for _, fi := range info {
		if name := fi.Name(); fi.IsDir() && name[0] != '.' {
			categoryPath := filepath.Join(dirName, name)
			c, err := loadCategory(categoryPath)
			if err == nil {
				cf.Categories[c.name] = c
			} else {
				log.Printf("Error loading category %s: %v", name, err)
			}
		}
	}

	return nil
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
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "allow":
		c.action = ALLOW
	case "ignore":
		c.action = IGNORE
	case "block":
		c.action = BLOCK
	case "acl":
		c.action = ACL
	case "":
		// No-op.
	default:
		return nil, fmt.Errorf("unrecognized action %s in %s", s, confFile)
	}

	s, _ = conf.Get("invisible")
	if s != "" {
		c.invisible, err = strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			log.Printf("Invalid setting for 'invisible' in %s: %q", confFile, s)
		}
	}

	ruleFiles, err := filepath.Glob(filepath.Join(dirname, "*.list"))
	if err != nil {
		return nil, fmt.Errorf("error listing rule files: %v", err)
	}
	sort.Strings(ruleFiles)
	for _, list := range ruleFiles {
		r, err := os.Open(list)
		if err != nil {
			log.Println(err)
			continue
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
func (cf *config) collectRules() {
	for _, c := range cf.Categories {
		for rule, _ := range c.weights {
			switch rule.t {
			case contentPhrase:
				cf.ContentPhraseList.addPhrase(rule.content)
			case imageHash:
				content := rule.content
				threshold := -1
				if dash := strings.Index(content, "-"); dash != -1 {
					t, err := strconv.Atoi(content[dash+1:])
					if err != nil {
						log.Printf("%v: %v", rule, err)
						continue
					}
					threshold = t
					content = content[:dash]
				}
				h, err := dhash.Parse(content)
				if err != nil {
					log.Printf("%v: %v", rule, err)
					continue
				}
				cf.ImageHashes = append(cf.ImageHashes, dhashWithThreshold{h, threshold})
			default:
				cf.URLRules.AddRule(rule)
			}
		}
	}
	cf.ContentPhraseList.findFallbackNodes(0, nil)
	cf.URLRules.finalize()
}

// score returns c's score for a page that matched
// the rules in tally. The keys are the rule names, and the values
// are the counts of how many times each rule was matched.
func (c *category) score(tally map[rule]int, conf *config) int {
	total := 0
	weights := c.weights
	for r, count := range tally {
		w := weights[r]
		if conf.CountOnce {
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
func (cf *config) categoryScores(tally map[rule]int) map[string]int {
	if len(tally) == 0 {
		return nil
	}

	scores := make(map[string]int)
	for _, c := range cf.Categories {
		s := c.score(tally, cf)
		if s != 0 {
			scores[c.name] = s
		}
	}
	return scores
}
