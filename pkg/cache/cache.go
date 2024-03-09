package cache

import (
	"sync"
	"time"
)

type (
	Cache[T any] struct {
		cache map[string]*cacheEntry[T]
		mutex *sync.Mutex
		ttl   time.Duration
	}

	cacheEntry[T any] struct {
		value     *T
		timestamp time.Time
	}
)

func New[T any](ttl time.Duration) *Cache[T] {
	c := &Cache[T]{
		cache: make(map[string]*cacheEntry[T]),
		mutex: &sync.Mutex{},
		ttl:   ttl,
	}

	go c.cleanup()

	return c
}

func (c *Cache[T]) Get(key string) *T {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, ok := c.cache[key]; ok {
		if time.Since(entry.timestamp) > c.ttl {
			delete(c.cache, key)
			return nil
		}
		return entry.value
	}

	return nil
}

func (c *Cache[T]) Flush() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache = make(map[string]*cacheEntry[T])
}

func (c *Cache[T]) Set(key string, value *T) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache[key] = &cacheEntry[T]{
		value:     value,
		timestamp: time.Now(),
	}
}

func (c *Cache[T]) cleanup() {
	for {
		time.Sleep(c.ttl)

		c.mutex.Lock()
		for key, entry := range c.cache {
			if time.Since(entry.timestamp) > c.ttl {
				delete(c.cache, key)
			}
		}
		c.mutex.Unlock()
	}
}
