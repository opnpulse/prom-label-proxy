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
	"strings"
	"testing"
)

func mustTestRoutes(t *testing.T, upstream string) *routes {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	r, err := NewRoutes(u, "tenant_id", HTTPFormEnforcer{ParameterName: "tenant_id"})
	if err != nil {
		t.Fatalf("NewRoutes: %v", err)
	}
	return r
}

func TestVictoriaPathsOmitZeroProject(t *testing.T) {
	if got := VictoriaWritePath(3, 0); got != "/insert/3/prometheus/api/v1/write" {
		t.Errorf("write path = %q", got)
	}
	if got := VictoriaSelectPrefix(3, 0); got != "/select/3/prometheus" {
		t.Errorf("select prefix = %q", got)
	}
	// A non-zero project is carried, so introducing projects later needs no change.
	if got := VictoriaWritePath(3, 7); got != "/insert/3:7/prometheus/api/v1/write" {
		t.Errorf("write path with project = %q", got)
	}
	// The largest account the backends parse must render intact.
	if got := VictoriaSelectPrefix(4294967295, 0); got != "/select/4294967295/prometheus" {
		t.Errorf("select prefix at the ceiling = %q", got)
	}
}

func TestApplyPathRewriteReplacesPathAndStripsHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	req.Header.Set("Thanos-Tenant", "ace.user.3")
	req = req.WithContext(WithVictoriaMetricsWrite(req.Context(), 3, 0, ""))

	applyPathRewrite(req)

	if req.URL.Path != "/insert/3/prometheus/api/v1/write" {
		t.Errorf("path = %q", req.URL.Path)
	}
	// The header meant something only to Thanos; leaving it would pass an unread
	// tenant hint to a backend that takes the tenant from the URL.
	if got := req.Header.Get("Thanos-Tenant"); got != "" {
		t.Errorf("Thanos-Tenant = %q, want it stripped", got)
	}
}

func TestApplyPathRewritePrefixesForSelect(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
	req = req.WithContext(WithVictoriaMetricsSelect(req.Context(), 42, 0, ""))

	applyPathRewrite(req)

	if req.URL.Path != "/select/42/prometheus/api/v1/query" {
		t.Errorf("path = %q", req.URL.Path)
	}
	if req.URL.Query().Get("query") != "up" {
		t.Error("the query must survive the rewrite")
	}
}

// Without a rewrite in context the request is untouched, which is what leaves the
// Thanos and ClickHouse paths exactly as they were.
func TestApplyPathRewriteIsNoOpWithoutContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	req.Header.Set("Thanos-Tenant", "ace.user.3")

	applyPathRewrite(req)

	if req.URL.Path != "/api/v1/receive" {
		t.Errorf("path = %q, want it unchanged", req.URL.Path)
	}
	if req.Header.Get("Thanos-Tenant") != "ace.user.3" {
		t.Error("the Thanos tenant header must survive when no rewrite applies")
	}
}

// The receive route must apply the rewrite before proxying, since that is the only
// point where the tenant has been settled.
func TestReceiveRouteAppliesRewrite(t *testing.T) {
	var seenPath, seenTenant string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenTenant = r.Header.Get("Thanos-Tenant")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	req.Header.Set("Thanos-Tenant", "ace.user.9")
	req = req.WithContext(WithVictoriaMetricsWrite(req.Context(), 9, 0, ""))
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if seenPath != "/insert/9/prometheus/api/v1/write" {
		t.Errorf("upstream path = %q", seenPath)
	}
	if seenTenant != "" {
		t.Errorf("upstream saw Thanos-Tenant = %q, want it stripped", seenTenant)
	}
}

// The Thanos write path must reach the receiver untouched.
func TestReceiveRouteLeavesThanosAlone(t *testing.T) {
	var seenPath, seenTenant string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenTenant = r.Header.Get("Thanos-Tenant")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	req.Header.Set("Thanos-Tenant", "ace.user.3")
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)

	if seenPath != "/api/v1/receive" {
		t.Errorf("upstream path = %q, want the original", seenPath)
	}
	if seenTenant != "ace.user.3" {
		t.Errorf("upstream saw Thanos-Tenant = %q, want it preserved", seenTenant)
	}
}

// The metrics query route must place the select prefix on the bare API path, not in
// front of the routing segment, or vmselect sees a path it cannot parse.
func TestMetricsRouteAppliesSelectPrefix(t *testing.T) {
	var seenPath, seenQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenQuery = r.URL.Query().Get("query")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	// This is what the /telemetry/ handler forwards for a metrics read.
	req := httptest.NewRequest(http.MethodGet, "/metrics/api/v1/query?query=up", nil)
	req = req.WithContext(WithVictoriaMetricsSelect(req.Context(), 3, 0, ""))
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if seenPath != "/select/3/prometheus/api/v1/query" {
		t.Errorf("upstream path = %q", seenPath)
	}
	if seenQuery != "up" {
		t.Errorf("upstream query = %q, want the caller's query preserved", seenQuery)
	}
}

// Without a rewrite the metrics route behaves exactly as before, which is what
// leaves the Thanos read path alone.
func TestMetricsRouteUnchangedForThanos(t *testing.T) {
	var seenPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/metrics/api/v1/query?query=up", nil)
	rec := httptest.NewRecorder()
	routes.ServeHTTP(rec, req)

	if seenPath != "/api/v1/query" {
		t.Errorf("upstream path = %q, want the prefix merely stripped", seenPath)
	}
}

// Every range and label endpoint the Perses datasource is allowed to call must land
// under the tenant prefix, not just the instant query.
func TestSelectPrefixCoversEveryAllowedEndpoint(t *testing.T) {
	upstreamPaths := map[string]string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPaths[r.Header.Get("X-Probe")] = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	for _, endpoint := range []string{
		"/api/v1/query",
		"/api/v1/query_range",
		"/api/v1/series",
		"/api/v1/labels",
		"/api/v1/label/job/values",
		"/api/v1/metadata",
	} {
		req := httptest.NewRequest(http.MethodGet, "/metrics"+endpoint, nil)
		req.Header.Set("X-Probe", endpoint)
		req = req.WithContext(WithVictoriaMetricsSelect(req.Context(), 42, 0, ""))
		routes.ServeHTTP(httptest.NewRecorder(), req)

		want := "/select/42/prometheus" + endpoint
		if got := upstreamPaths[endpoint]; got != want {
			t.Errorf("%s reached upstream as %q, want %q", endpoint, got, want)
		}
	}
}

// With several retention tiers each tenant must reach its own instance, otherwise
// data lands in the wrong retention.
func TestReceiveRoutesToTheTenantInstance(t *testing.T) {
	var hitA, hitB string
	instanceA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitA = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer instanceA.Close()
	instanceB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitB = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer instanceB.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fallback upstream was used for %s, want the tenant instance", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer fallback.Close()

	t.Setenv("METRICS_URL", fallback.URL)
	t.Setenv("LOGS_URL", fallback.URL)
	t.Setenv("TRACES_URL", fallback.URL)

	routes := mustTestRoutes(t, fallback.URL)

	for _, tc := range []struct {
		account  int64
		upstream string
	}{
		{account: 3, upstream: instanceA.URL},
		{account: 9, upstream: instanceB.URL},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
		req = req.WithContext(WithVictoriaMetricsWrite(req.Context(), tc.account, 0, tc.upstream))
		routes.ServeHTTP(httptest.NewRecorder(), req)
	}

	if hitA != "/insert/3/prometheus/api/v1/write" {
		t.Errorf("instance A saw %q", hitA)
	}
	if hitB != "/insert/9/prometheus/api/v1/write" {
		t.Errorf("instance B saw %q", hitB)
	}
}

// A single instance stack has no override and must still reach METRICS_URL.
func TestReceiveFallsBackToThePillarURL(t *testing.T) {
	var seen string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	req = req.WithContext(WithVictoriaMetricsWrite(req.Context(), 3, 0, ""))
	routes.ServeHTTP(httptest.NewRecorder(), req)

	if seen != "/insert/3/prometheus/api/v1/write" {
		t.Errorf("upstream saw %q", seen)
	}
}

// The tenant headers are the whole isolation mechanism for logs and traces, so a
// value the caller supplied must be replaced, never merged with or appended to.
func TestTenantHeadersOverrideAnythingTheCallerSent(t *testing.T) {
	for _, tc := range []struct {
		name string
		with func(req *http.Request) *http.Request
		path string
	}{
		{
			name: "logs",
			with: func(req *http.Request) *http.Request {
				return req.WithContext(WithVictoriaLogsWrite(req.Context(), 3, 0, ""))
			},
			path: VictoriaLogsInsertPath,
		},
		{
			name: "traces",
			with: func(req *http.Request) *http.Request {
				return req.WithContext(WithVictoriaTracesWrite(req.Context(), 3, 0, ""))
			},
			path: VictoriaTracesInsertPath,
		},
	} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		// A spoke trying to write into another tenant's account.
		req.Header.Add("AccountID", "999")
		req.Header.Add("AccountID", "1000")
		req.Header.Set("ProjectID", "77")
		req = tc.with(req)

		applyPathRewrite(req)

		if got := req.Header.Values("AccountID"); len(got) != 1 || got[0] != "3" {
			t.Errorf("%s: AccountID = %v, want exactly [3]", tc.name, got)
		}
		if got := req.Header.Values("ProjectID"); len(got) != 1 || got[0] != "0" {
			t.Errorf("%s: ProjectID = %v, want exactly [0]", tc.name, got)
		}
		if req.URL.Path != tc.path {
			t.Errorf("%s: path = %q, want %q", tc.name, req.URL.Path, tc.path)
		}
	}
}

// Logs and traces can run different backends, so each route must rewrite only for
// its own pillar and leave a ClickHouse pillar alone.
func TestLogsAndTracesRoutesRewriteIndependently(t *testing.T) {
	type hit struct {
		path    string
		account string
	}
	seen := map[string]hit{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Header.Get("X-Probe")] = hit{path: r.URL.Path, account: r.Header.Get("AccountID")}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	// Logs on VictoriaLogs, traces left on ClickHouse.
	logsReq := httptest.NewRequest(http.MethodPost, "/api/v1/logs?database=default", nil)
	logsReq.Header.Set("X-Probe", "logs")
	logsReq = logsReq.WithContext(WithVictoriaLogsWrite(logsReq.Context(), 42, 0, ""))
	routes.ServeHTTP(httptest.NewRecorder(), logsReq)

	tracesReq := httptest.NewRequest(http.MethodPost, "/api/v1/traces?database=default", nil)
	tracesReq.Header.Set("X-Probe", "traces")
	routes.ServeHTTP(httptest.NewRecorder(), tracesReq)

	if got := seen["logs"]; got.path != VictoriaLogsInsertPath || got.account != "42" {
		t.Errorf("logs reached upstream as %+v, want the OTLP path under account 42", got)
	}
	// A ClickHouse pillar still arrives at the root with no tenant header.
	if got := seen["traces"]; got.path != "/" || got.account != "" {
		t.Errorf("traces reached upstream as %+v, want the ClickHouse root", got)
	}
}

func TestLogsAndTracesRouteToTheirOwnInstances(t *testing.T) {
	var logsHit, tracesHit string
	logsInstance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logsHit = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer logsInstance.Close()
	tracesInstance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracesHit = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer tracesInstance.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("fallback was used for %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer fallback.Close()

	t.Setenv("METRICS_URL", fallback.URL)
	t.Setenv("LOGS_URL", fallback.URL)
	t.Setenv("TRACES_URL", fallback.URL)

	routes := mustTestRoutes(t, fallback.URL)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logs", nil)
	req = req.WithContext(WithVictoriaLogsWrite(req.Context(), 3, 0, logsInstance.URL))
	routes.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/traces", nil)
	req = req.WithContext(WithVictoriaTracesWrite(req.Context(), 3, 0, tracesInstance.URL))
	routes.ServeHTTP(httptest.NewRecorder(), req)

	if logsHit != VictoriaLogsInsertPath {
		t.Errorf("logs instance saw %q", logsHit)
	}
	if tracesHit != VictoriaTracesInsertPath {
		t.Errorf("traces instance saw %q", tracesHit)
	}
}

// Confinement is a request parameter, not spliced text, so VictoriaLogs ANDs it
// into the parsed filter. These are the queries a splice would have got wrong.
func TestNamespaceConfinementSurvivesHostileQueries(t *testing.T) {
	var seen struct {
		query   string
		filters []string
		account string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.query = r.URL.Query().Get("query")
		seen.filters = r.URL.Query()["extra_filters"]
		seen.account = r.Header.Get("AccountID")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)
	confinement := NamespaceExtraFilter("acme")

	for _, query := range []string{
		`error`,
		`error | stats count()`,
		// a pipe inside a quoted string
		`"a|b"`,
		// a query that already names a namespace
		`k8s.namespace.name:"other"`,
		// a comment that would hide a splice point
		`error # | drop everything`,
		// a subquery, which a splice would leave unconstrained
		`error AND k8s.pod.name:in(_time:1h | fields k8s.pod.name)`,
		// unbalanced quote
		`"unterminated`,
	} {
		req := httptest.NewRequest(http.MethodGet, "/logs/select/logsql/query?query="+url.QueryEscape(query), nil)
		req = req.WithContext(WithVictoriaLogsSelect(req.Context(), 3, 0, "", confinement))
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("query %q: status %d", query, rec.Code)
			continue
		}
		// The query reaches the backend untouched; confinement rides alongside it.
		if seen.query != query {
			t.Errorf("query %q was altered to %q", query, seen.query)
		}
		if len(seen.filters) != 1 || seen.filters[0] != confinement {
			t.Errorf("query %q: extra_filters = %v, want exactly [%s]", query, seen.filters, confinement)
		}
		if seen.account != "3" {
			t.Errorf("query %q: AccountID = %q", query, seen.account)
		}
	}
}

// A caller supplying extra_filters can only narrow what it sees, since
// VictoriaLogs ANDs every value, but ours must always be present.
func TestCallerExtraFiltersCannotDisplaceOurs(t *testing.T) {
	var filters []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filters = r.URL.Query()["extra_filters"]
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)
	confinement := NamespaceExtraFilter("acme")

	req := httptest.NewRequest(http.MethodGet,
		`/logs/select/logsql/query?query=error&extra_filters=`+url.QueryEscape(`{"k8s.namespace.name":"other"}`), nil)
	req = req.WithContext(WithVictoriaLogsSelect(req.Context(), 3, 0, "", confinement))
	routes.ServeHTTP(httptest.NewRecorder(), req)

	found := false
	for _, f := range filters {
		if f == confinement {
			found = true
		}
	}
	if !found {
		t.Fatalf("our confinement is missing from %v", filters)
	}
}

// A read must never reach an ingestion endpoint, or a query could write data.
func TestReadPathCannotReachIngestion(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	for _, path := range []string{
		"/logs" + VictoriaLogsInsertPath,
		"/logs/insert/jsonline",
		"/traces" + VictoriaTracesInsertPath,
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		if strings.HasPrefix(path, "/traces") {
			req = req.WithContext(WithVictoriaTracesSelect(req.Context(), 3, 0, ""))
		} else {
			req = req.WithContext(WithVictoriaLogsSelect(req.Context(), 3, 0, "", ""))
		}
		rec := httptest.NewRecorder()
		routes.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", path, rec.Code)
		}
	}
	if reached {
		t.Fatal("an ingestion path was proxied through the read route")
	}
}

// The Perses plugins speak each product's own query API, so those paths must pass
// through with the routing segment removed and nothing else changed.
func TestReadPathsReachTheProductQueryAPIs(t *testing.T) {
	seen := map[string]string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Header.Get("X-Probe")] = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	cases := []struct{ segment, endpoint string }{
		{"/logs", "/select/logsql/query"},
		{"/logs", "/select/logsql/hits"},
		{"/logs", "/select/logsql/field_values"},
		// the four paths the Perses Tempo datasource calls
		{"/traces", "/select/tempo/api/search"},
		{"/traces", "/select/tempo/api/v2/search/tags"},
		{"/traces", "/select/tempo/api/v2/search/tag/service.name/values"},
		{"/traces", "/select/tempo/api/v2/traces/abc123"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.segment+tc.endpoint, nil)
		req.Header.Set("X-Probe", tc.endpoint)
		if tc.segment == "/traces" {
			req = req.WithContext(WithVictoriaTracesSelect(req.Context(), 7, 0, ""))
		} else {
			req = req.WithContext(WithVictoriaLogsSelect(req.Context(), 7, 0, "", ""))
		}
		routes.ServeHTTP(httptest.NewRecorder(), req)

		if got := seen[tc.endpoint]; got != tc.endpoint {
			t.Errorf("%s%s reached upstream as %q", tc.segment, tc.endpoint, got)
		}
	}
}

// A ClickHouse pillar keeps its old behaviour: root path, no tenant headers.
func TestClickHouseReadUnchanged(t *testing.T) {
	var path, account string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, account = r.URL.Path, r.Header.Get("AccountID")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("METRICS_URL", upstream.URL)
	t.Setenv("LOGS_URL", upstream.URL)
	t.Setenv("TRACES_URL", upstream.URL)

	routes := mustTestRoutes(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/logs?query=SELECT+1&database=ace_user_3", nil)
	routes.ServeHTTP(httptest.NewRecorder(), req)

	if path != "/" || account != "" {
		t.Errorf("clickhouse read reached upstream as path=%q account=%q, want the root with no tenant header", path, account)
	}
}

func TestNamespaceExtraFilterIsJSON(t *testing.T) {
	got := NamespaceExtraFilter("acme")
	if got != `{"k8s.namespace.name":"acme"}` {
		t.Errorf("filter = %q", got)
	}
	// A namespace with a quote must not break out of the JSON.
	got = NamespaceExtraFilter(`a"b`)
	if got != `{"k8s.namespace.name":"a\"b"}` {
		t.Errorf("escaped filter = %q", got)
	}
}

// With one instance per retention tier, sending every read to a single upstream
// means most tenants see nothing.
func TestMetricsReadReachesTheTenantInstance(t *testing.T) {
	var tierAHit, tierBHit string
	tierA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tierAHit = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer tierA.Close()
	tierB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tierBHit = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer tierB.Close()

	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("read fell back to the single upstream for %s", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer fallback.Close()

	t.Setenv("METRICS_URL", fallback.URL)
	t.Setenv("LOGS_URL", fallback.URL)
	t.Setenv("TRACES_URL", fallback.URL)

	routes := mustTestRoutes(t, fallback.URL)

	for _, tc := range []struct {
		account  int64
		upstream string
	}{{3, tierA.URL}, {9, tierB.URL}} {
		req := httptest.NewRequest(http.MethodGet, "/metrics/api/v1/query?query=up", nil)
		req = req.WithContext(WithVictoriaMetricsSelect(req.Context(), tc.account, 0, tc.upstream))
		routes.ServeHTTP(httptest.NewRecorder(), req)
	}

	if tierAHit != "/select/3/prometheus/api/v1/query" {
		t.Errorf("tier A saw %q", tierAHit)
	}
	if tierBHit != "/select/9/prometheus/api/v1/query" {
		t.Errorf("tier B saw %q", tierBHit)
	}
}
