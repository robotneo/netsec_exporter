package core

import "sync"

var (
	collectors = map[string]Collector{}
	mu         sync.RWMutex
)

func Register(c Collector) {
	mu.Lock()
	defer mu.Unlock()
	collectors[c.Name()] = c
}

func GetCollector(vendor string) (Collector, bool) {
	mu.RLock()
	defer mu.RUnlock()
	c, ok := collectors[vendor]
	return c, ok
}
