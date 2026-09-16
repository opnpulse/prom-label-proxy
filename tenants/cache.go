package tenants

import (
	"context"
	"sync/atomic"
)

// apiResponse is the wire format from GET /api/v1/trickster/revocations.
type apiResponse struct {
	RevokedOwners   []string `json:"revokedOwners"`
	RevokedClusters []string `json:"revokedClusters"`
}

// Route addresses one tenant in the Victoria backends: a URL segment for
// VictoriaMetrics, a header for VictoriaLogs and VictoriaTraces.
type Route struct {
	AccountID int64
	ProjectID int64
	Metrics   Endpoint
	Logs      Endpoint
	Traces    Endpoint
}

// Endpoint is where one pillar lives, resolved by the operator from the backend's
// own address helper. Reads and writes differ in cluster mode.
type Endpoint struct {
	Instance string
	ReadURL  string
	WriteURL string
}

// Addressable reports whether the tenant has a usable account coordinate. Without
// one it must be refused, since account 0 is where untagged writes land.
func (r Route) Addressable() bool {
	return r.AccountID > 0
}

// Backends names the storage behind each pillar, as the deployed stack declares it.
type Backends struct {
	Metrics string
	Logs    string
	Traces  string
	// MetricsMode is the VictoriaMetrics deploymentMode, lowercased; empty otherwise.
	MetricsMode string
}

// VictoriaMetricsStandalone reports a single-node VictoriaMetrics, which has no
// tenant URLs. Anything but Cluster is single-node, as the operator reads it.
func (b Backends) VictoriaMetricsStandalone() bool {
	return b.Metrics == "victoriametrics" && b.MetricsMode != "cluster"
}

// ClusterClaims is what a cluster's certificate carries in its OU fields, read
// from the Tenant CR instead for callers that hold no per-cluster certificate.
type ClusterClaims struct {
	Owner        string
	EnableTenant bool
}

// snapshot is an immutable view of tenant state built once per refresh cycle.
type snapshot struct {
	owners        map[string]struct{}
	clusters      map[string]struct{}
	tenantNames   map[string]string        // tenantName → tenantID
	routes        map[string]Route         // tenantID → Route
	clusterClaims map[string]ClusterClaims // cluster name → claims
	backends      Backends
	// backendsKnown records whether this refresh actually read the stack, so a
	// failed read keeps the last confirmed answer instead of reverting.
	backendsKnown bool
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

// Refresh atomically replaces the snapshot. An unreadable stack keeps the last
// confirmed backends: defaulting would point a Victoria stack at Thanos.
func (c *Cache) Refresh(ctx context.Context, f *Fetcher) error {
	s, err := f.Fetch(ctx)
	if err != nil {
		return err
	}
	if !s.backendsKnown {
		if prev := c.load(); prev != nil && prev.backendsKnown {
			s.backends = prev.backends
			s.backendsKnown = true
		}
	}
	c.store(s)
	return nil
}

// FetchOnce performs an initial blocking fetch and populates the cache.
// Intended to be called before the HTTP server starts accepting connections.
func (c *Cache) FetchOnce(ctx context.Context, f *Fetcher) error {
	return c.Refresh(ctx, f)
}

// Backends returns the per-pillar backends the stack declares. Before the first
// fetch it reports the pre-existing stack rather than guessing.
func (c *Cache) Backends() Backends {
	s := c.load()
	if s == nil {
		return defaultBackends()
	}
	return s.backends
}

// Route returns the backend coordinates for a tenantID.
func (c *Cache) Route(tenantID string) (Route, bool) {
	s := c.load()
	if s == nil {
		return Route{}, false
	}
	r, ok := s.routes[tenantID]
	return r, ok
}

// ClusterClaims returns the claims recorded for a cluster tenant. Absent means
// the cluster is unknown, which callers must refuse rather than default.
func (c *Cache) ClusterClaims(cluster string) (ClusterClaims, bool) {
	s := c.load()
	if s == nil {
		return ClusterClaims{}, false
	}
	claims, ok := s.clusterClaims[cluster]
	return claims, ok
}

// ResolveTenantID maps a tenantName from a Tenant CRD spec to its tenantID.
func (c *Cache) ResolveTenantID(tenantName string) (string, bool) {
	s := c.load()
	if s == nil {
		return "", false
	}
	id, ok := s.tenantNames[tenantName]
	return id, ok
}
