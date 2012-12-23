package main

// A scorecard holds the scores calculated for a page.
type scorecard struct {
	tally   map[rule]int   // count of matches for each rule
	scores  map[string]int // score for each category
	blocked []string       // categories that cause the page to be blocked
	action  action         // action to take for the page
}

// calculate calculates category scores and finds out whether the page
// needs to be blocked, based on c.tally and the group that user belongs to.
func (c *scorecard) calculate(user string) {
	c.scores = categoryScores(c.tally)
	c.blocked = blockedCategories(c.scores, whichGroup[user])
	if len(c.blocked) > 0 {
		c.action = BLOCK
	} else {
		c.action = ALLOW
	}
}
