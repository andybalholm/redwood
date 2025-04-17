package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/andybalholm/cascadia"
	"go.starlark.net/starlark"
	"golang.org/x/net/html"
)

// An HTMLNode is a Starlark wrapper for an html.Node, with a selectolax-like
// interface.
type HTMLNode struct {
	frozen bool
	node   *html.Node
}

func (n *HTMLNode) String() string {
	return fmt.Sprintf("HTMLNode(%q)", n.node.Data)
}

func (n *HTMLNode) Type() string {
	return "HTMLNode"
}

func (n *HTMLNode) Freeze() {
	if n.frozen {
		return
	}
	n.frozen = true
}

func (n *HTMLNode) Truth() starlark.Bool {
	return true
}

func (n *HTMLNode) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: HTMLNode")
}

var htmlNodeAttrNames = []string{"css", "css_first", "decompose", "html", "attrs"}

func (n *HTMLNode) AttrNames() []string {
	return htmlNodeAttrNames
}

func (n *HTMLNode) Attr(name string) (starlark.Value, error) {
	switch name {
	case "attrs":
		return &AttrDict{
			frozen: n.frozen,
			node:   n.node,
		}, nil

	case "html":
		buf := new(bytes.Buffer)
		if err := html.Render(buf, n.node); err != nil {
			return nil, err
		}
		return starlark.String(buf.Bytes()), nil

	case "css":
		return starlark.NewBuiltin(name, htmlNodeCSS).BindReceiver(n), nil
	case "css_first":
		return starlark.NewBuiltin(name, htmlNodeCSSFirst).BindReceiver(n), nil
	case "decompose":
		return starlark.NewBuiltin(name, htmlNodeDecompose).BindReceiver(n), nil
	default:
		return nil, nil
	}
}

func htmlNodeCSS(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	n := fn.Receiver().(*HTMLNode)

	var query string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &query); err != nil {
		return nil, err
	}

	sel, err := cascadia.ParseGroup(query)
	if err != nil {
		return nil, err
	}

	var result []starlark.Value
	if sel.Match(n.node) {
		result = append(result, n)
	}
	for _, matched := range cascadia.QueryAll(n.node, sel) {
		result = append(result, &HTMLNode{node: matched, frozen: n.frozen})
	}

	return starlark.NewList(result), nil
}

func htmlNodeCSSFirst(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	n := fn.Receiver().(*HTMLNode)

	var query string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &query); err != nil {
		return nil, err
	}

	sel, err := cascadia.ParseGroup(query)
	if err != nil {
		return nil, err
	}

	if sel.Match(n.node) {
		return n, nil
	}
	matched := cascadia.Query(n.node, sel)
	if matched == nil {
		return starlark.None, nil
	}

	return &HTMLNode{node: matched, frozen: n.frozen}, nil
}

func htmlNodeDecompose(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	n := fn.Receiver().(*HTMLNode)

	if n.frozen {
		return nil, errors.New("can't decompose a frozen HTMLNode")
	}

	n.node.Parent.RemoveChild(n.node)
	return starlark.None, nil
}

// An AttrDict is a dictionary-like object that represents the attributes of an
// HTML node.
type AttrDict struct {
	frozen    bool
	itercount int
	node      *html.Node
}

func (a *AttrDict) String() string {
	return fmt.Sprintf("<%s attributes, %d items>", a.node.Data, len(a.node.Attr))
}

func (a *AttrDict) Type() string {
	return "AttrDict"
}

func (a *AttrDict) Freeze() {
	if !a.frozen {
		a.frozen = true
	}
}

func (a *AttrDict) Truth() starlark.Bool {
	return starlark.Bool(len(a.node.Attr) > 0)
}

func (a *AttrDict) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: AttrDict")
}

type attrDictIterator struct {
	ss       *AttrDict
	elements []string
}

func (it *attrDictIterator) Next(p *starlark.Value) bool {
	if len(it.elements) > 0 {
		*p = starlark.String(it.elements[0])
		it.elements = it.elements[1:]
		return true
	}
	return false
}

func (it *attrDictIterator) Done() {
	if !it.ss.frozen {
		it.ss.itercount--
	}
}

func (a *AttrDict) Iterate() starlark.Iterator {
	if !a.frozen {
		a.itercount++
	}
	elements := make([]string, len(a.node.Attr))
	for i, attr := range a.node.Attr {
		elements[i] = attr.Key
	}
	return &attrDictIterator{
		ss:       a,
		elements: elements,
	}
}

func (a *AttrDict) Len() int {
	return len(a.node.Attr)
}

func (a *AttrDict) Get(k starlark.Value) (v starlark.Value, found bool, err error) {
	ks, ok := k.(starlark.String)
	if !ok {
		return nil, false, nil
	}

	for _, attr := range a.node.Attr {
		if attr.Key == string(ks) {
			return starlark.String(attr.Val), true, nil
		}
	}

	return nil, false, nil
}

func (a *AttrDict) SetKey(k, v starlark.Value) error {
	if a.frozen {
		return errors.New("can't modify a frozen AttrDict")
	}
	if a.itercount > 0 {
		return errors.New("can't modify an AttrDict during iteration")
	}
	ks, ok := k.(starlark.String)
	if !ok {
		return fmt.Errorf("keys for AttrDict must be String, not %s", k.Type())
	}
	vs, ok := v.(starlark.String)
	if !ok {
		return fmt.Errorf("values for AttrDict must be String, not %s", v.Type())
	}

	for _, attr := range a.node.Attr {
		if attr.Key == string(ks) {
			attr.Val = string(vs)
			return nil
		}
	}

	a.node.Attr = append(a.node.Attr, html.Attribute{
		Key: string(ks),
		Val: string(vs),
	})
	return nil
}

var attrDictAttrNames = []string{"get", "pop", "clear"}

func (a *AttrDict) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get", "pop":
		return starlark.NewBuiltin(name, attrDictGet).BindReceiver(a), nil
	case "clear":
		return starlark.NewBuiltin(name, attrDictClear).BindReceiver(a), nil
	default:
		return nil, nil
	}
}

func attrDictGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	pop := fn.Name() == "pop"

	a := fn.Receiver().(*AttrDict)
	if pop {
		if a.frozen {
			return nil, errors.New("can't modify a frozen AttrDict")
		}
		if a.itercount > 0 {
			return nil, errors.New("can't modify a AttrDict during iteration")
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

	for i, attr := range a.node.Attr {
		if attr.Key == key {
			if pop {
				a.node.Attr = slices.Delete(a.node.Attr, i, i+1)
			}
			return starlark.String(attr.Val), nil
		}
	}

	if pop {
		return nil, fmt.Errorf("key %q not in dict", key)
	}

	return defaultValue, nil
}

func attrDictClear(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	a := fn.Receiver().(*AttrDict)
	if a.frozen {
		return nil, errors.New("can't modify a frozen AttrDict")
	}
	if a.itercount > 0 {
		return nil, errors.New("can't modify an AttrDict during iteration")
	}
	a.node.Attr = a.node.Attr[:0]
	return starlark.None, nil
}

func (a *AttrDict) Items() (result []starlark.Tuple) {
	for _, attr := range a.node.Attr {
		result = append(result, starlark.Tuple{
			starlark.String(attr.Key),
			starlark.String(attr.Val),
		})
	}
	return result
}
