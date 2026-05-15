package revocation

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

var tenantGVR = schema.GroupVersionResource{
	Group:    "monitoring.k8s.appscode.com",
	Version:  "v1alpha1",
	Resource: "tenants",
}

// Fetcher lists Tenant CRDs and builds a revocation snapshot.
// Tenant is cluster-scoped, so no namespace is needed.
type Fetcher struct {
	client dynamic.Interface
}

// NewFetcher creates a Fetcher using in-cluster Kubernetes config.
func NewFetcher() (*Fetcher, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("revocation: in-cluster config: %w", err)
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("revocation: dynamic client: %w", err)
	}
	return &Fetcher{client: client}, nil
}

// Fetch lists all Tenant CRDs and returns a snapshot of revoked identities.
// tenantID with "cluster:" prefix → cluster revocation; otherwise → owner revocation.
func (f *Fetcher) Fetch(ctx context.Context) (*snapshot, error) {
	list, err := f.client.Resource(tenantGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("revocation: list tenants: %w", err)
	}
	return buildSnapshot(list), nil
}

func buildSnapshot(list *unstructured.UnstructuredList) *snapshot {
	s := &snapshot{
		owners:   make(map[string]struct{}),
		clusters: make(map[string]struct{}),
	}
	for _, item := range list.Items {
		revoked, _, _ := unstructured.NestedBool(item.Object, "spec", "revoked")
		if !revoked {
			continue
		}
		tenantID, _, _ := unstructured.NestedString(item.Object, "spec", "tenantID")
		if tenantID == "" {
			continue
		}
		if strings.HasPrefix(tenantID, "cluster:") {
			s.clusters[strings.TrimPrefix(tenantID, "cluster:")] = struct{}{}
		} else {
			s.owners[tenantID] = struct{}{}
		}
	}
	return s
}
