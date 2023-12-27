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
	"gopkg.in/yaml.v3"
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
	name        string                   // the directory name
	description string                   // the name presented to users
	action      action                   // the action to be taken with a page in this category
	weights     map[rule]weight          // the weight for each rule
	urlLists    map[string]*CuckooFilter // a cuckoo filter for each URL list in the category
	invisible   bool                     // use invisible GIF instead of block page
}

// LoadCategories loads the category configuration files
func (cf *config) LoadCategories(dirName string) error {
	if cf.Categories == nil {
		cf.Categories = map[string]*category{}
	}
	return cf.loadCategories(dirName, nil, dirName)
}

func (cf *config) loadCategories(dirName string, parent *category, rootDir string) error {
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
			c, err := loadCategory(categoryPath, parent, rootDir)
			if err != nil {
				log.Printf("Error loading category %s: %v", name, err)
				continue
			}
			cf.Categories[c.name] = c

			// Load child categories.
			err = cf.loadCategories(categoryPath, c, rootDir)
			if err != nil {
				log.Printf("Error loading child categories of %s: %v", c.name, err)
			}
		}
	}

	return nil
}

// loadCategory loads the configuration for one category
func loadCategory(dirname string, parent *category, rootDir string) (c *category, err error) {
	c = new(category)
	c.weights = make(map[rule]weight)
	c.name = filepath.Base(dirname)
	if parent != nil {
		c.name = parent.name + "/" + c.name
	}
	c.description = c.name

	confFile := filepath.Join(dirname, "category.conf")
	confData, err := os.ReadFile(confFile)
	if err != nil {
		return nil, err
	}

	var conf struct {
		Description      string
		Action           string
		Invisible        bool
		ParentMultiplier float64 `yaml:"parent_multiplier"`
		Includes         map[string]float64
	}
	err = yaml.Unmarshal(confData, &conf)
	if err != nil {
		return nil, err
	}

	c.description = conf.Description

	s := conf.Action
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

	c.invisible = conf.Invisible

	parentMultiplier := 1.0
	if conf.ParentMultiplier != 0 {
		parentMultiplier = conf.ParentMultiplier
		if parentMultiplier < 0 || parentMultiplier > 1 {
			log.Printf("Value (%f) out of range for 'parent_multiplier' in %s (must be between 0 and 1)", parentMultiplier, confFile)
			parentMultiplier = 1.0
		}
	}

	if parent != nil {
		// Copy rules from parent category.
		for r, w := range parent.weights {
			c.weights[r] = weight{
				points:    int(float64(w.points) * parentMultiplier),
				maxPoints: int(float64(w.maxPoints) * parentMultiplier),
			}
		}
	}

	includes := make([]string, 0, len(conf.Includes))
	for includedFile := range conf.Includes {
		includes = append(includes, includedFile)
	}
	sort.Strings(includes)
	for _, includedFile := range includes {
		multiplier := conf.Includes[includedFile]
		if !filepath.IsAbs(includedFile) {
			includedFile = filepath.Join(rootDir, includedFile)
		}
		switch strings.ToLower(filepath.Ext(includedFile)) {
		case ".list":
			loadRuleFile(c, includedFile, multiplier)
		case ".urllist":
			loadURLList(c, includedFile, multiplier)
		default:
			log.Printf("Included file (%s) has unsupported extension in %s", includedFile, confFile)
		}
	}

	ruleFiles, err := filepath.Glob(filepath.Join(dirname, "*.list"))
	if err != nil {
		return nil, fmt.Errorf("error listing rule files: %v", err)
	}
	sort.Strings(ruleFiles)
	for _, list := range ruleFiles {
		loadRuleFile(c, list, 1)
	}

	urlLists, err := filepath.Glob(filepath.Join(dirname, "*.urllist"))
	if err != nil {
		return nil, fmt.Errorf("error listing URL list files: %v", err)
	}
	sort.Strings(urlLists)
	for _, list := range urlLists {
		loadURLList(c, list, 1)
	}

	return c, nil
}

func loadRuleFile(c *category, filename string, multiplier float64) {
	r, err := os.Open(filename)
	if err != nil {
		log.Println(err)
		return
	}
	defer r.Close()
	cr := newConfigReader(r)

	defaultWeight := 0

	for {
		line, err := cr.ReadLine()
		if err != nil {
			break
		}

		r, line, err := parseCompoundRule(line)
		if err != nil {
			log.Printf("Error in line %d of %s: %s", cr.LineNo, filename, err)
			continue
		}

		var w weight
		n, _ := fmt.Sscan(line, &w.points, &w.maxPoints)
		if n == 0 {
			w.points = defaultWeight
		} else if multiplier != 1 {
			w.points = int(float64(w.points) * multiplier)
			w.maxPoints = int(float64(w.maxPoints) * multiplier)
		}

		if sr, ok := r.(simpleRule); ok && sr.t == defaultRule {
			defaultWeight = w.points
		} else {
			c.weights[r] = w
		}
	}
}

func loadURLList(c *category, filename string, multiplier float64) {
	r, err := os.Open(filename)
	if err != nil {
		log.Println(err)
		return
	}
	defer r.Close()
	cr := newConfigReader(r)

	var urls []string
	score := 1

	for {
		line, err := cr.ReadLine()
		if err != nil {
			break
		}

		if len(urls) == 0 {
			n, _ := fmt.Sscanf(line, "score %d", &score)
			if n == 1 {
				continue
			}
		}

		u := line
		if strings.HasSuffix(u, "/") {
			u = strings.TrimSuffix(u, "/")
		}
		u = strings.ToLower(u)

		urls = append(urls, u)
	}

	f := NewCuckooFilter(len(urls))
	for _, u := range urls {
		f.Insert(u)
	}

	if c.urlLists == nil {
		c.urlLists = make(map[string]*CuckooFilter)
	}
	c.urlLists[filename] = f
	c.weights[simpleRule{
		t:       urlList,
		content: filename,
	}] = weight{points: int(float64(score) * multiplier)}
}

func (cf *config) addRule(r rule) {
	switch r := r.(type) {
	case simpleRule:
		switch r.t {
		case contentPhrase:
			cf.ContentPhraseList.addPhrase(r.content)
		case imageHash:
			content := r.content
			threshold := -1
			if dash := strings.Index(content, "-"); dash != -1 {
				t, err := strconv.Atoi(content[dash+1:])
				if err != nil {
					log.Printf("%v: %v", r, err)
					return
				}
				threshold = t
				content = content[:dash]
			}
			h, err := dhash.Parse(content)
			if err != nil {
				log.Printf("%v: %v", r, err)
				return
			}
			cf.ImageHashes = append(cf.ImageHashes, dhashWithThreshold{h, threshold})
		default:
			cf.URLRules.AddRule(r)
		}
	case compoundRule:
		cf.addRule(r.left)
		cf.addRule(r.right)
		cf.CompoundRules = append(cf.CompoundRules, r)
	}
}

// collectRules collects the rules from all the categories and adds
// them to URLRules and phraseRules.
func (cf *config) collectRules() {
	for _, c := range cf.Categories {
		for r, _ := range c.weights {
			cf.addRule(r)
		}
		for filename, filter := range c.urlLists {
			cf.URLRules.urlLists[filename] = filter
		}
		c.urlLists = nil // to allow duplicates to be garbage-collected
	}
	cf.ContentPhraseList.findFallbackNodes(0, nil)
	cf.URLRules.finalize()
}

type ruleScore struct {
	Count int
	Score int
}

// score returns c's score for a page that matched
// the rules in tally. The keys are the rule names, and the values
// are the counts of how many times each rule was matched.
//
// If ruleScores is not nil, it will get an entry for each rule that contributes
// to the score for the category.
func (c *category) score(tally map[rule]int, conf *config, ruleScores map[string]ruleScore) int {
	total := 0
	weights := c.weights
	for r, count := range tally {
		w := weights[r]
		if w.points == 0 {
			continue
		}
		p := w.points * count
		if conf.CountOnce {
			p = w.points
		}
		if w.maxPoints != 0 && (p > 0 && p > w.maxPoints || p < 0 && p < w.maxPoints) {
			p = w.maxPoints
		}
		total += p
		if ruleScores != nil {
			ruleScores[r.String()] = ruleScore{count, p}
		}
	}
	return total
}

func (cf *config) applyCompoundRules(tally map[rule]int) {
	for _, cr := range cf.CompoundRules {
		left := tally[cr.left]
		right := tally[cr.right]
		combined := left
		switch cr.op {
		case "&":
			if right < left {
				combined = right
			}
		case "|":
			if right > left {
				combined = right
			}
		case "&!":
			if right != 0 {
				combined = 0
			}
		}
		if combined != 0 {
			tally[cr] = combined
		}
	}
}

// categoryScores returns a map containing a page's score for each category.
func (cf *config) categoryScores(tally map[rule]int) map[string]int {
	if len(tally) == 0 {
		return nil
	}

	cf.applyCompoundRules(tally)

	scores := make(map[string]int)
	for _, c := range cf.Categories {
		s := c.score(tally, cf, nil)
		if s != 0 {
			scores[c.name] = s
		}
	}
	return scores
}
