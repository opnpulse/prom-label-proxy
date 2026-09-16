package injectproxy

import (
	"net/http"
	"testing"
)

// ClickHouse rejects Authorization plus X-ClickHouse credentials, and every
// client library sends the former, so the proxy must drop it.
func TestClickHouseCredentialsReplaceTheCallers(t *testing.T) {
	t.Setenv("CLICKHOUSE_USER", "proxy")
	t.Setenv("CLICKHOUSE_PASSWORD", "secret")
	h := http.Header{}
	h.Set("Authorization", "Basic ZGVmYXVsdDo=")
	SetClickHouseCredentials(h)
	if h.Get("Authorization") != "" {
		t.Fatal("the caller's Authorization must be removed")
	}

	// What clickhouse-go sends when it has a TLS client certificate.
	h = http.Header{}
	h.Set("X-Clickhouse-Ssl-Certificate-Auth", "on")
	h.Set("X-Clickhouse-User", "default")
	SetClickHouseCredentials(h)
	if h.Get("X-Clickhouse-Ssl-Certificate-Auth") != "" {
		t.Fatal("certificate auth must be removed, or ClickHouse refuses it with the password")
	}
	if h.Get("X-Clickhouse-User") != "proxy" || h.Get("X-Clickhouse-Key") != "secret" {
		t.Fatalf("proxy credentials not set: %v", h)
	}

	t.Setenv("CLICKHOUSE_USER", "")
	h = http.Header{}
	h.Set("Authorization", "Basic x")
	SetClickHouseCredentials(h)
	if h.Get("Authorization") == "" {
		t.Fatal("without proxy credentials the caller's own must pass through")
	}
}

// Writes arrive on /api/v1/logs and /api/v1/traces; the router serves
// ClickHouse only under /logs and /traces, so each must map onto its own.
func TestClickHouseWritePathReachesARoute(t *testing.T) {
	for in, want := range map[string]string{
		"/api/v1/logs":   "/logs",
		"/api/v1/traces": "/traces",
	} {
		if got := ClickHouseWritePath(in); got != want {
			t.Errorf("ClickHouseWritePath(%q) = %q, want %q", in, got, want)
		}
	}
}
