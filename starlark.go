package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/qri-io/starlib/bsoup"
	"github.com/qri-io/starlib/encoding/base64"
	"github.com/qri-io/starlib/encoding/csv"
	"github.com/qri-io/starlib/encoding/yaml"
	"github.com/qri-io/starlib/hash"
	"github.com/qri-io/starlib/html"
	"github.com/qri-io/starlib/http"
	"github.com/qri-io/starlib/re"
	"go.starlark.net/lib/json"
	"go.starlark.net/lib/math"
	"go.starlark.net/lib/time"
	"go.starlark.net/repl"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

func init() {
	// Enable some Starlark language features that are specific to the Go implementation.
	resolve.AllowSet = true
	resolve.AllowLambda = true
	resolve.AllowRecursion = true
	resolve.AllowGlobalReassign = true

	starlark.Universe["json"] = json.Module
	starlark.Universe["time"] = time.Module
	starlark.Universe["math"] = math.Module

	for name, loader := range starlib {
		mod, err := loader()
		if err != nil {
			panic(err)
		}
		unwrapped, ok := mod[name]
		if !ok {
			panic(fmt.Errorf("wrong module name: %s", name))
		}
		starlark.Universe[name] = unwrapped
	}

	starlark.Universe["lookup_host"] = starlark.NewBuiltin("lookup_host", lookupHostStarlark)
}

var starlib = map[string]func() (starlark.StringDict, error){
	"re":     re.LoadModule,
	"bsoup":  bsoup.LoadModule,
	"base64": base64.LoadModule,
	"csv":    csv.LoadModule,
	"yaml":   yaml.LoadModule,
	"hash":   hash.LoadModule,
	"html":   html.LoadModule,
	"http":   http.LoadModule,
}

type starlarkFunction func(...starlark.Value) (starlark.Value, error)

func newStarlarkThread() *starlark.Thread {
	return &starlark.Thread{
		Print: func(t *starlark.Thread, msg string) {
			log.Println(msg)
		},
	}
}

func (c *config) loadStarlarkScripts() {
	if c.StarlarkFunctions == nil {
		c.StarlarkFunctions = make(map[string]starlarkFunction)
	}

	thread := newStarlarkThread()
	thread.Load = repl.MakeLoad()

	for _, script := range c.StarlarkScripts {
		defs, err := starlark.ExecFile(thread, script, nil, nil)
		if err != nil {
			log.Printf("Error loading starlark script %s:\n%s", script, formatStarlarkError(err))
			continue
		}

		// Collect the functions defined by the script.
		for k, v := range defs {
			if f, ok := v.(starlark.Callable); ok {
				if _, ok := c.StarlarkFunctions[k]; ok {
					log.Println("Multiple definitions of starlark function", k)
				}
				c.StarlarkFunctions[k] = func(args ...starlark.Value) (starlark.Value, error) {
					return starlark.Call(newStarlarkThread(), f, starlark.Tuple(args), nil)
				}
			}
		}
	}
}

func formatStarlarkError(err error) string {
	switch err := err.(type) {
	case *starlark.EvalError:
		return err.Backtrace()
	default:
		return err.Error()
	}
}

func assignStarlarkString(dest *string, val starlark.Value) error {
	switch val := val.(type) {
	case starlark.String:
		*dest = string(val)
		return nil
	default:
		return fmt.Errorf("a string is required, not %s", val.Type())
	}
}

// A StringSet is a set where all the elements are strings.
type StringSet struct {
	frozen    bool
	itercount int
	data      map[string]bool
}

func (s *StringSet) elements() []string {
	elems := make([]string, 0, len(s.data))
	for k, v := range s.data {
		if v {
			elems = append(elems, k)
		}
	}
	sort.Strings(elems)
	return elems
}

func (s *StringSet) String() string {
	b := new(bytes.Buffer)
	b.WriteString("{")
	for i, v := range s.elements() {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%q", v)
	}
	b.WriteString("}")
	return b.String()
}

func (s *StringSet) Type() string {
	return "StringSet"
}

func (s *StringSet) Freeze() {
	if !s.frozen {
		s.frozen = true
	}
}

func (s *StringSet) Truth() starlark.Bool {
	return starlark.Bool(len(s.data) > 0)
}

func (s *StringSet) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: StringSet")
}

type stringSetIterator struct {
	ss       *StringSet
	elements []string
}

func (it *stringSetIterator) Next(p *starlark.Value) bool {
	if len(it.elements) > 0 {
		*p = starlark.String(it.elements[0])
		it.elements = it.elements[1:]
		return true
	}
	return false
}

func (it *stringSetIterator) Done() {
	if !it.ss.frozen {
		it.ss.itercount--
	}
}

func (s *StringSet) Iterate() starlark.Iterator {
	if !s.frozen {
		s.itercount++
	}
	return &stringSetIterator{
		ss:       s,
		elements: s.elements(),
	}
}

func (s *StringSet) Len() int {
	return len(s.data)
}

func stringSetChangeElement(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	s := fn.Receiver().(*StringSet)
	if s.frozen {
		return nil, errors.New("can't modify a frozen StringSet")
	}
	if s.itercount > 0 {
		return nil, errors.New("can't modify a StringSet during iteration")
	}

	var item string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &item); err != nil {
		return nil, err
	}

	switch fn.Name() {
	case "add":
		s.data[item] = true
		return starlark.None, nil
	case "remove":
		if _, ok := s.data[item]; !ok {
			return nil, fmt.Errorf("KeyError: %q", item)
		}
		fallthrough
	case "discard":
		delete(s.data, item)
		return starlark.None, nil
	}

	panic("unreachable")
}

var stringSetAttrNames = []string{"add", "remove", "discard"}

func (s *StringSet) AttrNames() []string {
	return stringSetAttrNames
}

func (s *StringSet) Attr(name string) (starlark.Value, error) {
	switch name {
	case "add", "remove", "discard":
		return starlark.NewBuiltin(name, stringSetChangeElement).BindReceiver(s), nil
	default:
		return nil, nil
	}
}

func (s *StringSet) Binary(op syntax.Token, y starlark.Value, side starlark.Side) (starlark.Value, error) {
	if op == syntax.IN && side == starlark.Right {
		switch y := y.(type) {
		case starlark.String:
			return starlark.Bool(s.data[string(y)]), nil
		default:
			return starlark.False, nil
		}
	}

	return nil, nil
}

// A StringIntDict is a dictionary where the keys are strings and the values
// are integers.
type StringIntDict struct {
	frozen    bool
	itercount int
	data      map[string]int
}

func (s *StringIntDict) String() string {
	b := new(bytes.Buffer)
	b.WriteString("{")
	for i, k := range sortedKeys(s.data) {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(b, "%q: %d", k, s.data[k])
	}
	b.WriteString("}")
	return b.String()
}

func (s *StringIntDict) Type() string {
	return "StringIntDict"
}

func (s *StringIntDict) Freeze() {
	if !s.frozen {
		s.frozen = true
	}
}

func (s *StringIntDict) Truth() starlark.Bool {
	return starlark.Bool(len(s.data) > 0)
}

func (s *StringIntDict) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: StringIntDict")
}

type stringIntDictIterator struct {
	ss       *StringIntDict
	elements []string
}

func (it *stringIntDictIterator) Next(p *starlark.Value) bool {
	if len(it.elements) > 0 {
		*p = starlark.String(it.elements[0])
		it.elements = it.elements[1:]
		return true
	}
	return false
}

func (it *stringIntDictIterator) Done() {
	if !it.ss.frozen {
		it.ss.itercount--
	}
}

func (s *StringIntDict) Iterate() starlark.Iterator {
	if !s.frozen {
		s.itercount++
	}
	return &stringIntDictIterator{
		ss:       s,
		elements: sortedKeys(s.data),
	}
}

func (s *StringIntDict) Len() int {
	return len(s.data)
}

func (s *StringIntDict) Get(k starlark.Value) (v starlark.Value, found bool, err error) {
	ks, ok := k.(starlark.String)
	if !ok {
		return nil, false, nil
	}

	val, ok := s.data[string(ks)]
	if !ok {
		return nil, false, nil
	}
	return starlark.MakeInt(val), true, nil
}

func (s *StringIntDict) SetKey(k, v starlark.Value) error {
	ks, ok := k.(starlark.String)
	if !ok {
		return fmt.Errorf("keys for StringIntDict must be String, not %s", k.Type())
	}
	vi, ok := v.(starlark.Int)
	if !ok {
		return fmt.Errorf("values for StringIntDict must be Int, not %s", v.Type())
	}
	vi64, ok := vi.Int64()
	i := int(vi64)
	if !ok || vi64 != int64(i) {
		return fmt.Errorf("%d is too large to store in a StringIntDict", v)
	}

	s.data[string(ks)] = i
	return nil
}

var stringIntDictAttrNames = []string{"get", "pop"}

func (s *StringIntDict) AttrNames() []string {
	return stringIntDictAttrNames
}

func (s *StringIntDict) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get", "pop":
		return starlark.NewBuiltin(name, stringIntDictGet).BindReceiver(s), nil
	default:
		return nil, nil
	}
}

func stringIntDictGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	pop := fn.Name() == "pop"

	s := fn.Receiver().(*StringIntDict)
	if pop {
		if s.frozen {
			return nil, errors.New("can't modify a frozen StringIntDict")
		}
		if s.itercount > 0 {
			return nil, errors.New("can't modify a StringIntDict during iteration")
		}
	}

	var key string
	var defaultValue starlark.Value
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key, &defaultValue); err != nil {
		return nil, err
	}
	if defaultValue == nil && !pop {
		defaultValue = starlark.None
	}

	v, ok := s.data[key]
	if !ok {
		if defaultValue != nil {
			return defaultValue, nil
		}
		return nil, fmt.Errorf("key %q not in dict", key)
	}
	if pop {
		delete(s.data, key)
	}
	return starlark.MakeInt(v), nil
}

func (s *StringIntDict) Items() (result []starlark.Tuple) {
	for _, k := range sortedKeys(s.data) {
		result = append(result, starlark.Tuple{
			starlark.String(k),
			starlark.MakeInt(s.data[k]),
		})
	}
	return result
}

func lookupHostStarlark(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var host, server string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &host, &server); err != nil {
		return nil, err
	}

	var result string
	var err error
	if len(args) == 1 {
		result, err = lookupHost(host)
	} else {
		result, err = lookupHost(host, server)
	}
	return starlark.String(result), err
}
