package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"
)

func certRequest(cn string, dns []string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dns,
	}}}
	return r
}

// The forwarder listener trusts a header for cluster identity, so the identity
// behind that header is the whole basis for the trust.
func TestOnlyTheForwarderMayNameACluster(t *testing.T) {
	want := "otel-forwarder.monitoring.svc"

	if err := verifyForwarderIdentity(certRequest(want, nil), want); err != nil {
		t.Errorf("the forwarder's own common name must be accepted: %v", err)
	}
	if err := verifyForwarderIdentity(certRequest("other", []string{"x", want}), want); err != nil {
		t.Errorf("a matching DNS SAN must be accepted: %v", err)
	}

	for _, r := range []*http.Request{
		certRequest("prom-label-proxy.monitoring.svc", nil),
		certRequest("", nil),
		certRequest("other", []string{"unrelated.svc"}),
	} {
		if err := verifyForwarderIdentity(r, want); err == nil {
			t.Error("any other certificate must be refused: it could claim any cluster")
		}
	}
}

// Without a certificate the header is a free claim, so an unauthenticated
// request must never reach the handler.
func TestForwarderListenerRefusesRequestsWithoutACertificate(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "/api/v1/receive", nil)
	if err := verifyForwarderIdentity(r, "otel-forwarder.monitoring.svc"); err == nil {
		t.Fatal("a plaintext request must be refused")
	}
	r.TLS = &tls.ConnectionState{}
	if err := verifyForwarderIdentity(r, "otel-forwarder.monitoring.svc"); err == nil {
		t.Fatal("TLS without a client certificate must be refused")
	}
}
