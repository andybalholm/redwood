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
		if fi.IsDirectory() && fi.Name[0] != '.' {
			categoryPath := filepath.Join(dirname, fi.Name)
			c, err := loadCategory(categoryPath)
			if err == nil {
				categories = append(categories, c)
			} else {
				log.Printf("Error loading category %s: %v", fi.Name, err)
			}
		}
	}
}

// loadCategory loads the configuration for one category
func loadCategory(dirname string) (c *category, err os.Error) {
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
