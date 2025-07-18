package main

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/maypok86/otter/v2"
	starlark_time "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
)

func init() {
	starlark.Universe["Cache"] = starlark.NewBuiltin("Cache", newCache)
}

var (
	// caches provides a collection of named caches for Starlark scripts to
	// store data in.
	caches = make(map[string]*otter.Cache[string, starlark.Value])

	cacheLock sync.RWMutex
)

// getCache gets or creates a cache with the specified name, and sets its capacity.
func getCache(name string, capacity int) *otter.Cache[string, starlark.Value] {
	cacheLock.RLock()
	c, ok := caches[name]
	cacheLock.RUnlock()

	if ok {
		c.SetMaximum(uint64(capacity))
		return c
	}

	cacheLock.Lock()
	defer cacheLock.Unlock()

	// It's possible that another goroutine has created the cache by now.
	// If so, we don't want to create another one.
	c, ok = caches[name]
	if ok {
		c.SetMaximum(uint64(capacity))
		return c
	}

	c = otter.Must(&otter.Options[string, starlark.Value]{
		MaximumSize: capacity,
	})

	caches[name] = c
	return c
}

func newCache(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var capacity int
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &name, &capacity); err != nil {
		return nil, err
	}

	c := getCache(name, capacity)
	return &Cache{
		name:  name,
		cache: c,
	}, nil
}

// A Cache is a Starlark wrapper for a ristretto.Cache.
type Cache struct {
	name  string
	cache *otter.Cache[string, starlark.Value]
}

func (c *Cache) String() string {
	return fmt.Sprintf("Cache(%q)", c.name)
}

func (c *Cache) Type() string {
	return "Cache"
}

func (c *Cache) Freeze() {}

func (c *Cache) Truth() starlark.Bool {
	return true
}

func (c *Cache) Hash() (uint32, error) {
	return 0, errors.New("unhashable type: Cache")
}

var cacheAttrNames = []string{"del", "get", "set"}

func (c *Cache) AttrNames() []string {
	return cacheAttrNames
}

func (c *Cache) Attr(name string) (starlark.Value, error) {
	switch name {
	case "del":
		return starlark.NewBuiltin(name, cacheDel).BindReceiver(c), nil
	case "get":
		return starlark.NewBuiltin(name, cacheGet).BindReceiver(c), nil
	case "set":
		return starlark.NewBuiltin(name, cacheSet).BindReceiver(c), nil

	default:
		return nil, nil
	}
}

func cacheDel(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	c := fn.Receiver().(*Cache)

	var key string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	c.cache.Invalidate(key)
	return starlark.None, nil
}

func cacheGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	c := fn.Receiver().(*Cache)

	var key string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	val, ok := c.cache.GetIfPresent(key)
	if !ok {
		return starlark.None, nil
	}
	return val, nil
}

func cacheSet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	c := fn.Receiver().(*Cache)

	var key string
	var val starlark.Value
	var ttl starlark_time.Duration
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &key, &val, &ttl); err != nil {
		return nil, err
	}

	val.Freeze()

	c.cache.Set(key, val)
	if ttl != 0 {
		c.cache.SetExpiresAfter(key, time.Duration(ttl))
	}
	return starlark.None, nil
}
