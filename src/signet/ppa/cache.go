package ppa

// Path Passport (ppa) cache - keyed by asn+sni.

import (
	"sync"
	"time"
)

type Entry struct {
	PathID    string    `json:"path_id"`
	PQCOk     bool      `json:"pqc_ok"`
	LastError string    `json:"last_hr"`
	TS        time.Time `json:"ts"`
}

type Cache struct {
	mu    sync.RWMutex
	data  map[string]Entry
	TTL   time.Duration
}

func New(ttl time.Duration) *Cache { return &Cache{data: map[string]Entry{}, TTL: ttl} }

func (c *Cache) Upsert(key string, e Entry) {
	c.mu.Lock(); defer c.mu.Unlock()
	e.TS = time.Now()
	c.data[key] = e
}

func (c *Cache) SnapshotClaims() []map[string]any {
	cut := time.Now().Add(-c.TTL)
	c.mu.RLock(); defer c.mu.RUnlock()
	out := []map[string]any{}
	for _, e := range c.data {
		if e.TS.Before(cut) { continue }
		out = append(out, map[string]any{
			"path_id": e.PathID,
			"pqc_ok": e.PQCOk,
			"last_hr": e.LastError,
		})
	}
	return out
}
