package main

import (
	"bytes"
	"errors"
	"fmt"

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

var htmlNodeAttrNames = []string{"css", "css_first", "decompose", "html"}

func (n *HTMLNode) AttrNames() []string {
	return htmlNodeAttrNames
}

func (n *HTMLNode) Attr(name string) (starlark.Value, error) {
	switch name {
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
