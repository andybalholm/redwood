package main

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	starlark_time "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
)

func init() {
	starlark.Universe["Cache"] = starlark.NewBuiltin("Cache", newCache)
}

var (
	// caches provides a collection of named caches for Starlark scripts to
	// store data in.
	caches = make(map[string]*ristretto.Cache)

	cacheLock sync.RWMutex
)

// getCache gets or creates a cache with the specified name, and sets its capacity.
func getCache(name string, capacity int64) *ristretto.Cache {
	cacheLock.RLock()
	c, ok := caches[name]
	cacheLock.RUnlock()

	if ok {
		c.UpdateMaxCost(capacity)
		return c
	}

	cacheLock.Lock()
	defer cacheLock.Unlock()

	// It's possible that another goroutine has created the cache by now.
	// If so, we don't want to create another one.
	c, ok = caches[name]
	if ok {
		c.UpdateMaxCost(capacity)
		return c
	}

	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: capacity * 10,
		MaxCost:     capacity,
		BufferItems: 64,
	})
	if err != nil {
		panic(err)
	}

	caches[name] = c
	return c
}

func newCache(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var capacity int64
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
	cache *ristretto.Cache
}

func (c *Cache) String() string {
	return fmt.Sprintf("Cache(%q)", c.name)
}

func (c *Cache) Type() string {
	return "Cache"
}

func (c *Cache) Freeze() {
	return
}

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

	c.cache.Del(key)
	return starlark.None, nil
}

func cacheGet(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	c := fn.Receiver().(*Cache)

	var key string
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}

	val, ok := c.cache.Get(key)
	if !ok {
		return starlark.None, nil
	}
	return val.(starlark.Value), nil
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

	c.cache.SetWithTTL(key, val, 1, time.Duration(ttl))
	return starlark.None, nil
}
