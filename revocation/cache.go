package revocation

import (
	"context"
	"sync/atomic"
)

// apiResponse is the wire format from GET /api/v1/trickster/revocations.
type apiResponse struct {
	RevokedOwners   []string `json:"revokedOwners"`
	RevokedClusters []string `json:"revokedClusters"`
}

// snapshot is an immutable revocation state built once per refresh cycle.
type snapshot struct {
	owners   map[string]struct{}
	clusters map[string]struct{}
}

// Cache holds the latest revocation snapshot behind an atomic pointer.
// Construct via NewCache; the zero value is not safe to use.
type Cache struct {
	val atomic.Value // stores *snapshot
}

// NewCache returns an empty, not-yet-loaded Cache.
func NewCache() *Cache {
	return &Cache{}
}

func (c *Cache) store(s *snapshot) {
	c.val.Store(s)
}

func (c *Cache) load() *snapshot {
	v := c.val.Load()
	if v == nil {
		return nil
	}
	return v.(*snapshot)
}

// IsReady reports whether the first successful fetch has completed.
func (c *Cache) IsReady() bool {
	return c.load() != nil
}

// IsRevoked returns whether owner or clusterName appear in the current snapshot.
// Safe to call concurrently from any number of goroutines.
func (c *Cache) IsRevoked(owner, clusterName string) (ownerRevoked, clusterRevoked bool) {
	s := c.load()
	if s == nil {
		return false, false
	}
	_, ownerRevoked = s.owners[owner]
	_, clusterRevoked = s.clusters[clusterName]
	return
}

// Refresh fetches a new snapshot and atomically replaces the current one.
func (c *Cache) Refresh(ctx context.Context, f *Fetcher) error {
	s, err := f.Fetch(ctx)
	if err != nil {
		return err
	}
	c.store(s)
	return nil
}

// FetchOnce performs an initial blocking fetch and populates the cache.
// Intended to be called before the HTTP server starts accepting connections.
func (c *Cache) FetchOnce(ctx context.Context, f *Fetcher) error {
	return c.Refresh(ctx, f)
}
