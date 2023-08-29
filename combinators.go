package main

import (
	"fmt"
	"strconv"
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

func takeAny1(set string) parser[string] {
	return func(input string) (string, string, error) {
		rest := strings.TrimLeft(input, set)
		if len(rest) == len(input) {
			return "", input, fmt.Errorf("nothing matching %q was found", set)
		}
		return input[:len(input)-len(rest)], rest, nil
	}
}

func opt[T any](p parser[T]) parser[*T] {
	return func(input string) (*T, string, error) {
		value, rest, err := p(input)
		if err != nil {
			return nil, input, nil
		}
		return &value, rest, nil
	}
}

func recognize2[T, U any](p1 parser[T], p2 parser[U]) parser[string] {
	return func(input string) (value string, rest string, err error) {
		_, rest, err = p1(input)
		if err != nil {
			return
		}
		_, rest, err = p2(rest)
		if err != nil {
			return
		}
		return input[:len(input)-len(rest)], rest, nil
	}
}

func mapWithError[T, U any](p parser[T], f func(T) (U, error)) parser[U] {
	return func(input string) (value U, rest string, err error) {
		v, rest, err := p(input)
		if err != nil {
			return value, input, err
		}
		value, err = f(v)
		return value, rest, err
	}
}

func integer(input string) (int, string, error) {
	s := strings.TrimLeft(input, " \t\r\n\f")
	return mapWithError(
		recognize2(opt(tag("-")), takeAny1("0123456789")),
		strconv.Atoi,
	)(s)
}
