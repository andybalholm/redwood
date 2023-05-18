package main

import (
	"fmt"
	"strings"
)

// parser combinators, inspired by nom

type parser[T any] func(input string) (value T, rest string, err error)

func tag(t string) parser[string] {
	return func(input string) (string, string, error) {
		s := strings.TrimLeft(input, " \t\r\n\f")
		if strings.HasPrefix(s, t) {
			return t, strings.TrimPrefix(s, t), nil
		} else {
			return "", input, fmt.Errorf("not found: %q", t)
		}
	}
}

func anyTag(tags ...string) parser[string] {
	return func(input string) (string, string, error) {
		s := strings.TrimLeft(input, " \t\r\n\f")
		for _, t := range tags {
			if strings.HasPrefix(s, t) {
				return t, strings.TrimPrefix(s, t), nil
			}
		}
		return "", input, fmt.Errorf("not found: %q", tags)
	}
}

func alt[T any](options ...parser[T]) parser[T] {
	return func(input string) (value T, rest string, err error) {
		for _, p := range options {
			value, rest, err = p(input)
			if err == nil {
				return
			}
		}
		return
	}
}

func delimited[T, U, V any](left parser[T], inner parser[U], right parser[V]) parser[U] {
	return func(input string) (value U, rest string, err error) {
		_, rest, err = left(input)
		if err != nil {
			return
		}
		value, rest, err = inner(rest)
		if err != nil {
			return
		}
		_, rest, err = right(rest)
		return
	}
}
