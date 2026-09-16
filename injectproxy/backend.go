// Copyright 2026 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package injectproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Backend names the storage behind one telemetry pillar. The proxy rewrites paths
// and headers differently per backend, so it has to be told which one is deployed.
type Backend string

const (
	BackendThanos          Backend = "thanos"
	BackendVictoriaMetrics Backend = "victoriametrics"
	BackendClickHouse      Backend = "clickhouse"
	BackendVictoriaLogs    Backend = "victorialogs"
	BackendVictoriaTraces  Backend = "victoriatraces"
)

// VictoriaWritePath is the remote write path for one tenant. The tenant is in the
// URL, not a label, so a caller cannot widen its scope by editing the payload.
func VictoriaWritePath(accountID, projectID int64) string {
	return "/insert/" + victoriaTenantToken(accountID, projectID) + "/prometheus/api/v1/write"
}

// VictoriaSelectPrefix is the query path prefix for one tenant on VictoriaMetrics.
func VictoriaSelectPrefix(accountID, projectID int64) string {
	return "/select/" + victoriaTenantToken(accountID, projectID) + "/prometheus"
}

// victoriaTenantToken renders the tenant coordinate. The project is omitted when it
// is zero, which is how VictoriaMetrics reads an absent one anyway.
func victoriaTenantToken(accountID, projectID int64) string {
	if projectID == 0 {
		return fmt.Sprintf("%d", accountID)
	}
	return fmt.Sprintf("%d:%d", accountID, projectID)
}

// rewriteKey carries a path rewrite decided by the caller, so the routing layer
// applies it without needing to know how the tenant was authenticated.
type rewriteKey struct{}

type pathRewrite struct {
	// Path replaces the request path outright.
	Path string
	// Prefix is prepended to the request path.
	Prefix string
	// StripHeaders are removed before the request leaves, so a tenant hint that
	// only meant something to the previous backend cannot reach the new one.
	StripHeaders []string
	// SetHeaders replace any value the caller sent. Used for the tenant headers the
	// logs and traces backends read, which a client must never be able to choose.
	SetHeaders map[string]string
	// Upstream overrides the destination for this request, used when retention is
	// expressed as one instance per tier and the tenant's data lives in one of them.
	Upstream string
	// RequirePathPrefix rejects the request unless the rewritten path starts with
	// it. Read paths set this so a query cannot reach an ingestion endpoint.
	RequirePathPrefix string
	// ExtraFilters constrains a VictoriaLogs query. A request parameter, not
	// spliced text, so it is ANDed into the parsed filter and pipes cannot escape.
	ExtraFilters string
	// Query replaces the whole query string, so a caller cannot add parameters.
	Query url.Values
	// ExtraLabels are added as extra_label parameters, which single-node
	// VictoriaMetrics ANDs into every series selector of a read.
	ExtraLabels []string
	// AllowedPaths limits a read to these API paths; empty allows any.
	AllowedPaths []string
}

// WithPathRewrite attaches a rewrite to be applied just before proxying.
func WithPathRewrite(ctx context.Context, rw pathRewrite) context.Context {
	return context.WithValue(ctx, rewriteKey{}, rw)
}

// WithVictoriaMetricsWrite attaches the remote write rewrite for a tenant. The
// Thanos header is dropped since VictoriaMetrics takes the tenant from the URL.
func WithVictoriaMetricsWrite(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		Path:         VictoriaWritePath(accountID, projectID),
		StripHeaders: []string{"THANOS-TENANT"},
		Upstream:     upstream,
	})
}

// WithVictoriaMetricsSelect attaches the query rewrite for a tenant, pointed at
// the instance holding its tier: vmselect, not the vminsert writes go to.
func WithVictoriaMetricsSelect(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		Prefix:   VictoriaSelectPrefix(accountID, projectID),
		Upstream: upstream,
	})
}

// Single-node VictoriaMetrics has no tenant URLs, so the tenant is a pair of
// labels. They match cluster mode's names, which the retention filters use.
const (
	VictoriaSingleWritePath   = "/api/v1/write"
	VictoriaAccountLabel      = "vm_account_id"
	VictoriaProjectLabel      = "vm_project_id"
	victoriaSingleLabelValues = "/api/v1/label/"
)

// victoriaSingleReadPaths are the query APIs a datasource needs. A VMSingle serves
// ingestion and admin on the same port, so nothing else may be reached.
var victoriaSingleReadPaths = []string{
	"/api/v1/query",
	"/api/v1/query_range",
	"/api/v1/query_exemplars",
	"/api/v1/series",
	"/api/v1/labels",
	"/api/v1/metadata",
	"/api/v1/status/buildinfo",
}

// victoriaTenantLabels renders the tenant as extra_label values.
func victoriaTenantLabels(accountID, projectID int64) []string {
	return []string{
		fmt.Sprintf("%s=%d", VictoriaAccountLabel, accountID),
		fmt.Sprintf("%s=%d", VictoriaProjectLabel, projectID),
	}
}

// WithVictoriaMetricsSingleWrite attaches the write rewrite for a VMSingle. The
// labels override any the payload carries, so a sender cannot pick a tenant.
func WithVictoriaMetricsSingleWrite(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		Path:         VictoriaSingleWritePath,
		StripHeaders: []string{"THANOS-TENANT"},
		Query:        url.Values{"extra_label": victoriaTenantLabels(accountID, projectID)},
		Upstream:     upstream,
	})
}

// WithVictoriaMetricsSingleSelect attaches the read rewrite for a VMSingle. A
// caller's own extra_label or matcher is ANDed with ours, so it can only narrow.
func WithVictoriaMetricsSingleSelect(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		ExtraLabels:  victoriaTenantLabels(accountID, projectID),
		AllowedPaths: victoriaSingleReadPaths,
		Upstream:     upstream,
	})
}

// allowedReadPath reports whether a rewrite permits path. Label values have the
// name in the path, so that one is matched by shape.
func allowedReadPath(rw pathRewrite, p string) bool {
	if len(rw.AllowedPaths) == 0 {
		return true
	}
	if p != path.Clean(p) {
		return false
	}
	for _, allowed := range rw.AllowedPaths {
		if p == allowed {
			return true
		}
	}
	name, ok := strings.CutPrefix(p, victoriaSingleLabelValues)
	name, ok2 := strings.CutSuffix(name, "/values")
	return ok && ok2 && name != "" && !strings.Contains(name, "/")
}

// Ingestion paths for the products that take OTLP over HTTP.
const (
	VictoriaLogsInsertPath   = "/insert/opentelemetry/v1/logs"
	VictoriaTracesInsertPath = "/insert/opentelemetry/v1/traces"

	// TempoSelectPrefix is where VictoriaTraces serves the Tempo API. Its Jaeger
	// API lacks the operations endpoint the Perses Jaeger plugin needs.
	TempoSelectPrefix = "/select/tempo"

	// LogsQLSelectPrefix is where VictoriaLogs serves its query API.
	LogsQLSelectPrefix = "/select/logsql"
)

// tenantHeaders are the headers VictoriaLogs and VictoriaTraces read the tenant
// from. Both parse them with ParseUint(s, 10, 32).
func tenantHeaders(accountID, projectID int64) map[string]string {
	return map[string]string{
		"AccountID": fmt.Sprintf("%d", accountID),
		"ProjectID": fmt.Sprintf("%d", projectID),
	}
}

// WithVictoriaLogsWrite attaches the OTLP ingestion rewrite for a tenant.
func WithVictoriaLogsWrite(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		Path:       VictoriaLogsInsertPath,
		SetHeaders: tenantHeaders(accountID, projectID),
		Upstream:   upstream,
	})
}

// WithVictoriaTracesWrite attaches the OTLP ingestion rewrite for a tenant.
func WithVictoriaTracesWrite(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		Path:       VictoriaTracesInsertPath,
		SetHeaders: tenantHeaders(accountID, projectID),
		Upstream:   upstream,
	})
}

// LogsNamespaceField is the field a client org log query is confined to. The agent
// emits k8s.namespace.name and VictoriaLogs flattens resource attributes as-is.
const LogsNamespaceField = "k8s.namespace.name"

// NamespaceExtraFilter renders the confinement VictoriaLogs applies to a query.
// The JSON form is turned into an exact match filter by VictoriaLogs itself.
func NamespaceExtraFilter(namespace string) string {
	b, err := json.Marshal(map[string]string{LogsNamespaceField: namespace})
	if err != nil {
		return ""
	}
	return string(b)
}

// WithVictoriaLogsSelect attaches the query rewrite for a tenant. Empty
// extraFilters is right for an org that owns the whole account.
func WithVictoriaLogsSelect(ctx context.Context, accountID, projectID int64, upstream, extraFilters string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		SetHeaders:        tenantHeaders(accountID, projectID),
		Upstream:          upstream,
		RequirePathPrefix: "/select/",
		ExtraFilters:      extraFilters,
	})
}

// WithVictoriaTracesSelect attaches the query rewrite for a tenant.
func WithVictoriaTracesSelect(ctx context.Context, accountID, projectID int64, upstream string) context.Context {
	return WithPathRewrite(ctx, pathRewrite{
		SetHeaders:        tenantHeaders(accountID, projectID),
		Upstream:          upstream,
		RequirePathPrefix: "/select/",
	})
}

// applyReadRewrite points a read at path and refuses anything outside the allowed
// prefix, so a query cannot reach ingestion. False means it already responded.
func applyReadRewrite(w http.ResponseWriter, req *http.Request, path string) bool {
	rw, ok := pathRewriteFrom(req.Context())
	if !ok {
		return true
	}
	if path == "" {
		path = "/"
	}
	req.URL.Path = path

	if rw.RequirePathPrefix != "" && !strings.HasPrefix(req.URL.Path, rw.RequirePathPrefix) {
		http.Error(w, "only query endpoints are reachable here", http.StatusForbidden)
		return false
	}

	if rw.ExtraFilters != "" {
		// Appended rather than replaced: VictoriaLogs ANDs every extra_filters
		// value, so a caller's own can only narrow what it already sees.
		q := req.URL.Query()
		q.Add("extra_filters", rw.ExtraFilters)
		req.URL.RawQuery = q.Encode()
	}

	applyPathRewrite(req)
	return true
}

func pathRewriteFrom(ctx context.Context) (pathRewrite, bool) {
	rw, ok := ctx.Value(rewriteKey{}).(pathRewrite)
	return rw, ok
}

// applyPathRewrite mutates req according to a rewrite attached upstream. It is a no
// op when none was attached, which is what keeps the Thanos path untouched.
func applyPathRewrite(req *http.Request) {
	rw, ok := pathRewriteFrom(req.Context())
	if !ok {
		return
	}
	if rw.Path != "" {
		req.URL.Path = rw.Path
	}
	if rw.Prefix != "" {
		req.URL.Path = rw.Prefix + req.URL.Path
	}
	for _, h := range rw.StripHeaders {
		req.Header.Del(h)
	}
	for h, v := range rw.SetHeaders {
		// Delete first so a caller cannot smuggle a second value past Set.
		req.Header.Del(h)
		req.Header.Set(h, v)
	}
	if rw.Query != nil {
		req.URL.RawQuery = rw.Query.Encode()
	}
	if len(rw.ExtraLabels) > 0 {
		q := req.URL.Query()
		for _, l := range rw.ExtraLabels {
			q.Add("extra_label", l)
		}
		req.URL.RawQuery = q.Encode()
	}
}

// upstreamOverride returns a per-request destination when one was attached.
func upstreamOverride(req *http.Request) (*url.URL, bool) {
	rw, ok := pathRewriteFrom(req.Context())
	if !ok || rw.Upstream == "" {
		return nil, false
	}
	u, err := url.Parse(rw.Upstream)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, false
	}
	return u, true
}
