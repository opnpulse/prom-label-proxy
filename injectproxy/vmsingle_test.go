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
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
)

type seenRequest struct {
	path   string
	query  url.Values
	tenant string
	hit    bool
}

func vmSingleUpstream(t *testing.T) (*routes, *seenRequest) {
	t.Helper()
	seen := &seenRequest{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = seenRequest{path: r.URL.Path, query: r.URL.Query(), tenant: r.Header.Get("Thanos-Tenant"), hit: true}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)
	return mustTestRoutes(t, upstream.URL), seen
}

// A VMSingle write goes to its plain path with the tenant as labels, and a
// caller's own query parameters are dropped so it cannot add a label of its own.
func TestVMSingleWriteStampsTheTenant(t *testing.T) {
	routes, seen := vmSingleUpstream(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive?extra_label=vm_account_id=1", nil)
	req.Header.Set("Thanos-Tenant", "ace.user.9")
	req = req.WithContext(WithVictoriaMetricsSingleWrite(req.Context(), 9, 0, ""))
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if seen.path != "/api/v1/write" {
		t.Errorf("upstream path = %q", seen.path)
	}
	if got := seen.query["extra_label"]; !slices.Equal(got, []string{"vm_account_id=9", "vm_project_id=0"}) {
		t.Errorf("extra_label = %q, want only the tenant's", got)
	}
	if seen.tenant != "" {
		t.Errorf("upstream saw Thanos-Tenant = %q, want it stripped", seen.tenant)
	}
}

// Each tier is its own VMSingle, so a write must reach the tenant's instance.
func TestVMSingleWriteReachesTheTenantInstance(t *testing.T) {
	routes, fallback := vmSingleUpstream(t)
	var tierPath string
	tier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tierPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer tier.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	req = req.WithContext(WithVictoriaMetricsSingleWrite(req.Context(), 9, 0, tier.URL))
	routes.ServeHTTP(httptest.NewRecorder(), req)

	if tierPath != "/api/v1/write" {
		t.Errorf("tier saw %q", tierPath)
	}
	if fallback.hit {
		t.Errorf("write fell back to the single upstream")
	}
}

// Reads keep the caller's query and gain the tenant labels, which VictoriaMetrics
// ANDs with any the caller sent, so they can only narrow.
func TestVMSingleReadEnforcesTheTenant(t *testing.T) {
	routes, seen := vmSingleUpstream(t)

	for _, endpoint := range []string{
		"/api/v1/query",
		"/api/v1/query_range",
		"/api/v1/series",
		"/api/v1/labels",
		"/api/v1/label/job/values",
		"/api/v1/metadata",
	} {
		*seen = seenRequest{}
		req := httptest.NewRequest(http.MethodGet, "/metrics"+endpoint+"?query=up&extra_label=vm_account_id=1", nil)
		req = req.WithContext(WithVictoriaMetricsSingleSelect(req.Context(), 3, 0, ""))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d", endpoint, rec.Code)
			continue
		}
		if seen.path != endpoint {
			t.Errorf("%s reached upstream as %q", endpoint, seen.path)
		}
		if seen.query.Get("query") != "up" {
			t.Errorf("%s: caller's query lost", endpoint)
		}
		got := seen.query["extra_label"]
		if !slices.Contains(got, "vm_account_id=3") || !slices.Contains(got, "vm_project_id=0") {
			t.Errorf("%s: extra_label = %q, want the tenant's added", endpoint, got)
		}
	}
}

// A VMSingle serves ingestion and admin on its query port, so a read must not
// reach anything but the query APIs.
func TestVMSingleReadCannotReachIngestionOrAdmin(t *testing.T) {
	routes, seen := vmSingleUpstream(t)

	for _, p := range []string{
		"/api/v1/write",
		"/api/v1/import",
		"/api/v1/import/prometheus",
		"/api/v1/admin/tsdb/delete_series",
		"/api/v1/export",
		"/api/v1/status/tsdb",
		"/internal/force_flush",
		"/snapshot/create",
		"/federate",
		"/metrics",
		"/vmui",
		"",
		"/api/v1/label/job/values/../../admin/tsdb/delete_series",
		"/api/v1/label//values",
		"/api/v1/label/a/b/values",
		"/api/v1/query/",
	} {
		*seen = seenRequest{}
		req := httptest.NewRequest(http.MethodPost, "/metrics"+p, nil)
		req = req.WithContext(WithVictoriaMetricsSingleSelect(req.Context(), 3, 0, ""))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)

		if seen.hit {
			t.Errorf("%q reached upstream as %q", p, seen.path)
		}
		if rec.Code == http.StatusOK {
			t.Errorf("%q: status 200, want a refusal", p)
		}
	}
}

// Cluster mode and Thanos must not gain the allowlist or the labels.
func TestVMClusterAndThanosReadsUnchanged(t *testing.T) {
	routes, seen := vmSingleUpstream(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics/api/v1/status/tsdb", nil)
	req = req.WithContext(WithVictoriaMetricsSelect(req.Context(), 3, 0, ""))
	routes.ServeHTTP(httptest.NewRecorder(), req)
	if seen.path != "/select/3/prometheus/api/v1/status/tsdb" || seen.query.Has("extra_label") {
		t.Errorf("cluster read reached upstream as %q %v", seen.path, seen.query)
	}

	*seen = seenRequest{}
	req = httptest.NewRequest(http.MethodGet, "/metrics/api/v1/status/tsdb", nil)
	routes.ServeHTTP(httptest.NewRecorder(), req)
	if seen.path != "/api/v1/status/tsdb" || seen.query.Has("extra_label") {
		t.Errorf("thanos read reached upstream as %q %v", seen.path, seen.query)
	}
}
