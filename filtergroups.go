package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// Filter groups—different rules for different groups of users.

// WhichGroup returns the group name for a username or IP address.
func (c *config) WhichGroup(user string) string {
	if g, ok := c.whichGroup[user]; ok {
		return g
	}

	ip := net.ParseIP(user)
	if ip == nil {
		return ""
	}

	for _, gr := range c.groupRanges {
		if gr.r.Contains(ip) {
			return gr.group
		}
	}

	return ""
}

// An IPRange represents a range of IP addresses.
type IPRange struct {
	first, last net.IP
}

func (r IPRange) String() string {
	return fmt.Sprintf("%s-%s", r.first, r.last)
}

// ParseIPRange parses s as an IP address range. It accepts ranges in the following forms:
// "10.1.10.0-10.1.10.255", "10.1.10.0-255", and "10.1.10.0/24".
func ParseIPRange(s string) (r IPRange, err error) {
	defer func() {
		// Make sure the IPv4 addresses are in 4-byte form.
		if r.first != nil && r.last != nil {
			if f4 := r.first.To4(); f4 != nil {
				r.first = f4
			}
			if f4 := r.last.To4(); f4 != nil {
				r.last = f4
			}
		}
	}()

	_, n, err := net.ParseCIDR(s)
	if err == nil {
		r.first = n.IP
		r.last = make(net.IP, len(n.IP))
		for i, b := range n.IP {
			r.last[i] = b | ^n.Mask[i]
		}
		return r, nil
	}
	err = nil

	dash := strings.Index(s, "-")
	if dash == -1 {
		err = fmt.Errorf("%q is not a valid IP address range", s)
		return
	}

	r.first = net.ParseIP(s[:dash])
	if r.first == nil {
		err = fmt.Errorf("%q does not begin with a valid IP address", s)
		return
	}

	last := s[dash+1:]
	r.last = net.ParseIP(last)
	if r.last != nil {
		return
	}

	lastByte, err := strconv.ParseUint(last, 10, 8)
	if err != nil {
		err = fmt.Errorf("%q does not end with a valid IP address or byte value", s)
		return
	}

	r.last = make(net.IP, len(r.first))
	copy(r.last, r.first)
	r.last[len(r.last)-1] = byte(lastByte)
	return
}

func (r IPRange) Contains(addr net.IP) bool {
	if a4 := addr.To4(); a4 != nil {
		addr = a4
	}
	if len(addr) != len(r.first) {
		return false
	}
	for i := range addr {
		if addr[i] < r.first[i] {
			return false
		}
		if addr[i] > r.first[i] {
			break
		}
	}
	for i := range addr {
		if addr[i] > r.last[i] {
			return false
		}
		if addr[i] < r.last[i] {
			break
		}
	}
	return true
}

type rangeToGroup struct {
	r     IPRange
	group string
}

// assignGroupMember assigns users to a filter group. s contains the group name and a
// space-separated list of users (either IP addresses or usernames).
func (c *config) assignGroupMember(s string) error {
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
		if strings.ContainsAny(user, "/-") {
			r, err := ParseIPRange(user)
			if err != nil {
				log.Println(err)
				continue
			}
			c.groupRanges = append(c.groupRanges, rangeToGroup{r, group})
		} else {
			c.whichGroup[user] = group
		}
	}

	return nil
}

// assignGroupAction assigns an action to a group/category combination (in s).
// The category comes first, than a space, then the group. If no group is
// specified, the default group is used.
func (c *config) assignGroupAction(s string, a action) error {
	group := ""
	space := strings.Index(s, " ")
	if space != -1 {
		group = strings.TrimSpace(s[space:])
		s = s[:space]
	}
	category := s

	actions := c.groupActions[group]
	if actions == nil {
		actions = make(map[string]action)
		c.groupActions[group] = actions
	}

	actions[category] = a
	return nil
}
