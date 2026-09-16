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

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Thanos keys series by a tenant_id label, so the parameter must still be set.
func TestEnforceNamespaceInjectsTenantIDForThanos(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
	rec := httptest.NewRecorder()

	if !enforceNamespace(rec, req, "arnob", false, true) {
		t.Fatal("enforceNamespace refused a plain org query")
	}
	if got := req.URL.Query().Get("tenant_id"); got != "arnob" {
		t.Errorf("tenant_id = %q, want arnob", got)
	}
}

// VictoriaMetrics carries the tenant in the path, so the parameter is meaningless
// there and must not be added.
func TestEnforceNamespaceSkipsTenantIDForVictoria(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
	rec := httptest.NewRecorder()

	if !enforceNamespace(rec, req, "arnob", false, false) {
		t.Fatal("enforceNamespace refused a plain org query")
	}
	if got := req.URL.Query().Get("tenant_id"); got != "" {
		t.Errorf("tenant_id = %q, want it absent", got)
	}
}

// Client org confinement is real enforcement, so it must apply on both backends
// regardless of whether tenant_id is injected.
func TestClientOrgNamespaceIsEnforcedOnBothBackends(t *testing.T) {
	for _, injectTenantID := range []bool{true, false} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/query?query=up", nil)
		rec := httptest.NewRecorder()

		if !enforceNamespace(rec, req, "acme", true, injectTenantID) {
			t.Fatalf("injectTenantID=%v: refused a client org query", injectTenantID)
		}
		got := req.URL.Query().Get("query")
		if !strings.Contains(got, `namespace="acme"`) {
			t.Errorf("injectTenantID=%v: query = %q, want a namespace matcher", injectTenantID, got)
		}
	}
}

// A client org naming someone else's namespace is refused rather than rewritten.
func TestClientOrgCannotNameAnotherNamespace(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, `/api/v1/query?query=up{namespace="other"}`, nil)
	rec := httptest.NewRecorder()

	if enforceNamespace(rec, req, "acme", true, false) {
		t.Fatal("a mismatched namespace should be refused")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// Form posts are how Perses sends queries, so the rewritten body has to be rebuilt.
func TestEnforceNamespaceRewritesFormPost(t *testing.T) {
	body := url.Values{"query": {"up"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/query", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	if !enforceNamespace(rec, req, "acme", true, false) {
		t.Fatal("enforceNamespace refused a form post")
	}

	rebuilt, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read rebuilt body: %v", err)
	}
	values, err := url.ParseQuery(string(rebuilt))
	if err != nil {
		t.Fatalf("parse rebuilt body: %v", err)
	}
	if q := values.Get("query"); !strings.Contains(q, `namespace="acme"`) {
		t.Errorf("rebuilt query = %q, want a namespace matcher", q)
	}
	if values.Get("tenant_id") != "" {
		t.Error("tenant_id must not appear in the rebuilt body for a Victoria backend")
	}
	if req.ContentLength != int64(len(rebuilt)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(rebuilt))
	}
}

func TestGetDBNameMatchesTheOperator(t *testing.T) {
	// The tenant operator computes the same name, so a mismatch would point reads at
	// a database that does not exist.
	if got := getDBName("ace.user.3", "spoke-1"); got != "ace_user_3" {
		t.Errorf("getDBName owner = %q, want ace_user_3", got)
	}
	if got := getDBName("default", "spoke-1"); got != "default_spoke_1" {
		t.Errorf("getDBName default = %q, want default_spoke_1", got)
	}
}
