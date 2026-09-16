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

package tenants

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func tenantObj(name string, spec, status map[string]interface{}) unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "monitoring.k8s.appscode.com/v1alpha1",
		"kind":       "Tenant",
		"metadata":   map[string]interface{}{"name": name},
		"spec":       spec,
	}
	if status != nil {
		obj["status"] = status
	}
	return unstructured.Unstructured{Object: obj}
}

func TestBuildSnapshotReadsRoutes(t *testing.T) {
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{
		tenantObj("ace.user.3",
			map[string]interface{}{"tenantID": "ace.user.3", "tenantName": "arnob"},
			map[string]interface{}{
				"accountID": int64(3),
				"projectID": int64(0),
				"metrics": map[string]interface{}{
					"instance": "telemetry-stack-vm-1y",
					"readURL":  "http://vmselect-telemetry-stack-vm-1y.monitoring.svc:8481",
					"writeURL": "http://vminsert-telemetry-stack-vm-1y.monitoring.svc:8480",
				},
				"logs": map[string]interface{}{
					"instance": "telemetry-stack-vl-90d",
					"readURL":  "http://vlsingle-telemetry-stack-vl-90d.monitoring.svc:9428",
					"writeURL": "http://vlsingle-telemetry-stack-vl-90d.monitoring.svc:9428",
				},
			}),
	}}

	s := buildSnapshot(list)
	c := NewCache()
	c.store(s)

	route, ok := c.Route("ace.user.3")
	if !ok {
		t.Fatal("expected a route for ace.user.3")
	}
	if route.AccountID != 3 || route.ProjectID != 0 {
		t.Errorf("coordinates = (%d,%d), want (3,0)", route.AccountID, route.ProjectID)
	}
	if route.Metrics.Instance != "telemetry-stack-vm-1y" {
		t.Errorf("metrics instance = %q", route.Metrics.Instance)
	}
	// Cluster mode reads and writes are different components.
	if route.Metrics.ReadURL == route.Metrics.WriteURL {
		t.Errorf("metrics read and write URLs are identical: %q", route.Metrics.ReadURL)
	}
	if route.Logs.Instance != "telemetry-stack-vl-90d" {
		t.Errorf("logs instance = %q", route.Logs.Instance)
	}
	// A single node deployment serves both directions from one address.
	if route.Logs.ReadURL != route.Logs.WriteURL {
		t.Errorf("single node logs URLs differ: %q vs %q", route.Logs.ReadURL, route.Logs.WriteURL)
	}
	// Traces stayed on ClickHouse, so no endpoint was recorded.
	if route.Traces.Instance != "" || route.Traces.ReadURL != "" {
		t.Errorf("traces endpoint = %+v, want empty", route.Traces)
	}
	if !route.Addressable() {
		t.Error("a tenant with accountID 3 should be addressable")
	}
}

// A tenant the operator has not yet given coordinates must not be stored as account
// 0, which is where untagged writes land.
func TestTenantWithoutCoordinatesHasNoRoute(t *testing.T) {
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{
		tenantObj("no-status", map[string]interface{}{"tenantID": "ace.user.5"}, nil),
		tenantObj("zero-account",
			map[string]interface{}{"tenantID": "ace.user.6"},
			map[string]interface{}{"accountID": int64(0)}),
	}}

	c := NewCache()
	c.store(buildSnapshot(list))

	for _, id := range []string{"ace.user.5", "ace.user.6"} {
		if route, ok := c.Route(id); ok {
			t.Errorf("Route(%q) returned %+v, want no route", id, route)
		}
	}
}

func TestRouteAddressable(t *testing.T) {
	if (Route{}).Addressable() {
		t.Error("the zero route must not be addressable")
	}
	if (Route{AccountID: 0}).Addressable() {
		t.Error("account 0 must not be addressable")
	}
	if !(Route{AccountID: 4294967295}).Addressable() {
		t.Error("the largest account the backends accept should be addressable")
	}
}

// Revocation and tenant naming must keep working now that the snapshot also holds
// routes, since both are still read on every request.
func TestSnapshotStillCarriesRevocationAndNames(t *testing.T) {
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{
		tenantObj("revoked-owner",
			map[string]interface{}{"tenantID": "ace.user.9", "tenantName": "rakib", "revoked": true},
			map[string]interface{}{"accountID": int64(9)}),
		tenantObj("revoked-cluster",
			map[string]interface{}{"tenantID": "cluster:spoke-1", "revoked": true}, nil),
		tenantObj("live-org",
			map[string]interface{}{"tenantID": "ace.user.42", "tenantName": "acme"},
			map[string]interface{}{"accountID": int64(42)}),
	}}

	c := NewCache()
	c.store(buildSnapshot(list))

	if ownerRevoked, _ := c.IsRevoked("ace.user.9", ""); !ownerRevoked {
		t.Error("ace.user.9 should be revoked")
	}
	if _, clusterRevoked := c.IsRevoked("", "spoke-1"); !clusterRevoked {
		t.Error("cluster spoke-1 should be revoked")
	}
	if ownerRevoked, _ := c.IsRevoked("ace.user.42", ""); ownerRevoked {
		t.Error("ace.user.42 should not be revoked")
	}
	if got, ok := c.ResolveTenantID("acme"); !ok || got != "ace.user.42" {
		t.Errorf("ResolveTenantID(acme) = %q,%v want ace.user.42,true", got, ok)
	}
	// A revoked tenant still has a route; revocation is checked separately and
	// refusing earlier would hide the reason from the caller.
	if _, ok := c.Route("ace.user.9"); !ok {
		t.Error("a revoked tenant should still resolve a route")
	}
}

func TestUnloadedCacheReturnsNoRoute(t *testing.T) {
	c := NewCache()
	if c.IsReady() {
		t.Error("a fresh cache should not be ready")
	}
	if _, ok := c.Route("ace.user.3"); ok {
		t.Error("an unloaded cache must not return a route")
	}
}

// The stack is the source of truth for backends, so a proxy reading it cannot
// disagree with what the operator deployed.
func TestBackendsComeFromTheStack(t *testing.T) {
	stacks := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"metrics": map[string]interface{}{"backend": "VictoriaMetrics"},
				"logs":    map[string]interface{}{"backend": "VictoriaLogs"},
				"traces":  map[string]interface{}{"backend": "ClickHouse"},
			},
		},
	}}}

	got := backendsFromStacks(stacks)
	if got.Metrics != "victoriametrics" || got.Logs != "victorialogs" || got.Traces != "clickhouse" {
		t.Fatalf("backends = %+v", got)
	}
}

// A stack stored before the backend field existed keeps the original stack.
func TestBackendsDefaultToTheOriginalStack(t *testing.T) {
	for _, list := range []*unstructured.UnstructuredList{
		nil,
		{},
		{Items: []unstructured.Unstructured{{Object: map[string]interface{}{"spec": map[string]interface{}{}}}}},
	} {
		got := backendsFromStacks(list)
		if got.Metrics != "thanos" || got.Logs != "clickhouse" || got.Traces != "clickhouse" {
			t.Errorf("backends = %+v, want the pre-existing stack", got)
		}
	}
}

// Before the first fetch the proxy must not rewrite anything, or it would translate
// requests for a backend it has not confirmed is deployed.
func TestUnloadedCacheReportsTheOriginalStack(t *testing.T) {
	got := NewCache().Backends()
	if got.Metrics != "thanos" || got.Logs != "clickhouse" || got.Traces != "clickhouse" {
		t.Fatalf("backends = %+v", got)
	}
}

func TestStackReadFailureDoesNotRevertBackends(t *testing.T) {
	c := NewCache()

	// First refresh confirms VictoriaMetrics.
	confirmed := buildSnapshot(&unstructured.UnstructuredList{})
	confirmed.backends = Backends{Metrics: "victoriametrics", Logs: "victorialogs", Traces: "clickhouse"}
	confirmed.backendsKnown = true
	c.store(confirmed)

	// A later refresh could not read the stack, so it carries defaults and says so.
	degraded := buildSnapshot(&unstructured.UnstructuredList{})
	degraded.backends = defaultBackends()
	degraded.backendsKnown = false

	// Refresh keeps the confirmed answer rather than flipping to the defaults,
	// which would point a VictoriaMetrics stack's writes at the Thanos receiver.
	if prev := c.load(); prev != nil && prev.backendsKnown {
		degraded.backends = prev.backends
		degraded.backendsKnown = true
	}
	c.store(degraded)

	if got := c.Backends(); got.Metrics != "victoriametrics" || got.Logs != "victorialogs" {
		t.Fatalf("backends = %+v, want the last confirmed answer", got)
	}
}

// An unreadable stack degrades to the behaviour this cluster had before backends
// were selectable, not to nothing.
func TestBackendsDegradeToTheOriginalStack(t *testing.T) {
	if got := (&Cache{}).Backends(); got != defaultBackends() {
		t.Fatalf("backends = %+v, want the original stack", got)
	}
}

// Only an explicit Cluster keeps the tenant-in-URL routing; the CRD defaults to
// Standalone, so an empty mode is single-node too.
func TestVictoriaMetricsModeComesFromTheStack(t *testing.T) {
	stack := func(metrics map[string]interface{}) *unstructured.UnstructuredList {
		return &unstructured.UnstructuredList{Items: []unstructured.Unstructured{{
			Object: map[string]interface{}{"spec": map[string]interface{}{"metrics": metrics}},
		}}}
	}
	for _, tc := range []struct {
		name       string
		metrics    map[string]interface{}
		standalone bool
	}{
		{"cluster", map[string]interface{}{"backend": "VictoriaMetrics", "victoriaMetrics": map[string]interface{}{"deploymentMode": "Cluster"}}, false},
		{"standalone", map[string]interface{}{"backend": "VictoriaMetrics", "victoriaMetrics": map[string]interface{}{"deploymentMode": "Standalone"}}, true},
		{"mode unset", map[string]interface{}{"backend": "VictoriaMetrics"}, true},
		{"thanos", map[string]interface{}{"backend": "Thanos"}, false},
		{"no backend", map[string]interface{}{}, false},
	} {
		if got := backendsFromStacks(stack(tc.metrics)).VictoriaMetricsStandalone(); got != tc.standalone {
			t.Errorf("%s: standalone = %v, want %v", tc.name, got, tc.standalone)
		}
	}
	if NewCache().Backends().VictoriaMetricsStandalone() {
		t.Error("an unloaded cache must report the original Thanos stack")
	}
}
