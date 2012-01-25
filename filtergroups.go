package main

import (
	"fmt"
	"strings"
)

// Filter groups—different rules for different groups of users.

// whichGroup maps usernames or IP addresses to filter group names.
var whichGroup = map[string]string{}

// groupActions maps groups and categories to actions.
// For example, if members of the admin group should be able to access sites
// in the proxies category, groupActions["admin"]["proxies"] = ALLOW.
// groupActions[""] contains the actions that apply to users who are not
// members of any group.
var groupActions = map[string]map[string]action{}

var groupMember = newActiveFlag("group", "", "assign a user to a filter group (--group 'group-name user-name')", assignGroupMember)

var groupBlock = newActiveFlag("block", "", "block a category for a filter group (--block 'category group')",
	func(s string) error {
		return assignGroupAction(s, BLOCK)
	})

var groupIgnore = newActiveFlag("ignore", "", "ignore a category for a filter group (--ignore 'category group')",
	func(s string) error {
		return assignGroupAction(s, IGNORE)
	})

var groupAllow = newActiveFlag("allow", "", "allow a category for a filter group (--allow 'category group')",
	func(s string) error {
		return assignGroupAction(s, ALLOW)
	})

// assignGroupMember assigns users to a filter group. s contains the group name and a
// space-separated list of users (either IP addresses or usernames).
func assignGroupMember(s string) error {
	space := strings.Index(s, " ")
	if space == -1 {
		return fmt.Errorf("invalid group assignment '%s': must be at least 2 words (group name and user)", s)
	}
	group := s[:space]
	s = strings.TrimSpace(s[space:])

	for _, user := range strings.Split(s, " ") {
		if user == "" {
			continue
		}
		whichGroup[user] = group
	}

	return nil
}

// assignGroupAction assigns an action to a group/category combination (in s).
// The category comes first, than a space, then the group. If no group is
// specified, the default group is used.
func assignGroupAction(s string, a action) error {
	group := ""
	space := strings.Index(s, " ")
	if space != -1 {
		group = strings.TrimSpace(s[space:])
		s = s[:space]
	}
	category := s

	actions := groupActions[group]
	if actions == nil {
		actions = make(map[string]action)
		groupActions[group] = actions
	}

	actions[category] = a
	return nil
}
