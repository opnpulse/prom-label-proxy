package tenants

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func claimsTenantObj(tenantID, owner string, enableTenant, revoked bool) unstructured.Unstructured {
	spec := map[string]interface{}{"tenantID": tenantID}
	if owner != "" {
		spec["owner"] = owner
	}
	if enableTenant {
		spec["enableTenant"] = true
	}
	if revoked {
		spec["revoked"] = true
	}
	return unstructured.Unstructured{Object: map[string]interface{}{"spec": spec}}
}

// The forwarder has no per-cluster certificate, so the claims a certificate
// would have carried have to come from the CR it was issued from.
func TestClusterClaimsComeFromTheTenant(t *testing.T) {
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{
		claimsTenantObj("cluster:prod-a", "acme", false, false),
		claimsTenantObj("cluster:prod-b", "acme", true, false),
		claimsTenantObj("team-x", "acme", true, false), // a client tenant, not a cluster
	}}
	c := NewCache()
	c.store(buildSnapshot(list))

	a, ok := c.ClusterClaims("prod-a")
	if !ok {
		t.Fatal("prod-a should be known")
	}
	if a.Owner != "acme" || a.EnableTenant {
		t.Errorf("prod-a claims = %+v, want owner acme without the tenant right", a)
	}

	b, ok := c.ClusterClaims("prod-b")
	if !ok || !b.EnableTenant {
		t.Errorf("prod-b should carry the tenant right, got %+v ok=%v", b, ok)
	}

	// An unknown cluster must not resolve to anything a caller could use.
	if _, ok := c.ClusterClaims("does-not-exist"); ok {
		t.Error("an unknown cluster must not produce claims")
	}
	if _, ok := c.ClusterClaims("team-x"); ok {
		t.Error("a client tenant is not a cluster and must not produce cluster claims")
	}
}

// Revocation still has to hold for a caller arriving without a certificate.
func TestRevokedClusterStillHasClaimsButIsRevoked(t *testing.T) {
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{
		claimsTenantObj("cluster:prod-a", "acme", false, true),
	}}
	c := NewCache()
	c.store(buildSnapshot(list))

	if _, ok := c.ClusterClaims("prod-a"); !ok {
		t.Fatal("claims should still resolve; the revocation check is what refuses")
	}
	_, clusterRevoked := c.IsRevoked("acme", "prod-a")
	if !clusterRevoked {
		t.Error("prod-a must read as revoked")
	}
}

// A cluster tenant with no owner cannot be spoken for.
func TestClusterWithoutAnOwnerProducesNoClaims(t *testing.T) {
	list := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{
		claimsTenantObj("cluster:orphan", "", false, false),
	}}
	c := NewCache()
	c.store(buildSnapshot(list))
	if _, ok := c.ClusterClaims("orphan"); ok {
		t.Error("a cluster with no owner must not produce claims")
	}
}
