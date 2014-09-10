package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var dayAbbreviations = map[rune]time.Weekday{
	'S': time.Sunday,
	'M': time.Monday,
	'T': time.Tuesday,
	'W': time.Wednesday,
	'H': time.Thursday,
	'F': time.Friday,
	'A': time.Saturday,
}

// ParseWeekdayList takes a string of one-letter weekday abbreviations (like
// "MWF" and returns an array of booleans, one for each day of the week, which
// are true if that day was included. The weekday abbreviations are SMTWHFA.
func ParseWeekdayList(list string) (days [7]bool, err error) {
	list = strings.ToUpper(list)
	for _, c := range list {
		d, ok := dayAbbreviations[c]
		if !ok {
			return [7]bool{}, fmt.Errorf("invalid weekday abbreviation (%c) in %q", c, list)
		}
		if days[d] {
			return [7]bool{}, fmt.Errorf("repeated day (%v) in %q", d, list)
		}
		days[d] = true
	}
	return days, nil
}

// A TimeRange is a range of times within a day.
type TimeRange struct {
	Start, End time.Time
}

// ParseTimeRange parses a time range in the format hh:mm-hh:mm (24-hour).
func ParseTimeRange(s string) (r TimeRange, err error) {
	dash := strings.Index(s, "-")
	if dash == -1 {
		return TimeRange{}, fmt.Errorf("invalid time range string %q: no hyphen", s)
	}

	start := s[:dash]
	end := s[dash+1:]

	r.Start, err = time.Parse("15:04", start)
	if err != nil {
		return TimeRange{}, fmt.Errorf("invalid time range string %q: %v", s, err)
	}
	r.End, err = time.Parse("15:04", end)
	if err != nil {
		return TimeRange{}, fmt.Errorf("invalid time range string %q: %v", s, err)
	}

	if !r.Start.Before(r.End) {
		return TimeRange{}, fmt.Errorf("invalid time range %q (Did you forget to use 24-hour clock?)", s)
	}

	return r, nil
}

// A WeeklySchedule is a set of time periods, occurring on certain days of the
// week and repeating each week.
type WeeklySchedule struct {
	Days  [7]bool
	Times []TimeRange
}

// ParseWeeklySchedule reads an optional weekday list, and any number of
// TimeRanges, into a WeeklySchedule.
func ParseWeeklySchedule(src []string) (schedule WeeklySchedule, err error) {
	if len(src) == 0 {
		return WeeklySchedule{}, errors.New("no data")
	}

	if days := src[0]; days != "" && 'A' <= days[0] && days[0] <= 'Z' {
		src = src[1:]
		schedule.Days, err = ParseWeekdayList(days)
		if err != nil {
			return WeeklySchedule{}, err
		}
	} else {
		for i := range schedule.Days {
			schedule.Days[i] = true
		}
	}

	for _, times := range src {
		tr, err := ParseTimeRange(times)
		if err != nil {
			return WeeklySchedule{}, err
		}
		schedule.Times = append(schedule.Times, tr)
	}

	return schedule, nil
}

func (w WeeklySchedule) Contains(t time.Time) bool {
	if !w.Days[t.Weekday()] {
		return false
	}

	if len(w.Times) == 0 {
		return true
	}

	h, m, _ := t.Clock()
	clockTime := time.Date(0, 1, 1, h, m, 0, 0, time.UTC)

	for _, tr := range w.Times {
		if !(clockTime.Before(tr.Start) || clockTime.After(tr.End)) {
			return true
		}
	}

	return false
}
