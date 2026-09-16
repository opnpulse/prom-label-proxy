package tenants

import (
	"context"
	"fmt"
	"log"
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

var telemetryStackGVR = schema.GroupVersionResource{
	Group:    "monitoring.k8s.appscode.com",
	Version:  "v1alpha1",
	Resource: "telemetrystacks",
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
		return nil, fmt.Errorf("tenants: in-cluster config: %w", err)
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("tenants: dynamic client: %w", err)
	}
	return &Fetcher{client: client}, nil
}

// Fetch lists all Tenant CRDs: which identities are revoked, and how each tenant
// is addressed in the backends. A "cluster:" prefix means cluster revocation.
func (f *Fetcher) Fetch(ctx context.Context) (*snapshot, error) {
	list, err := f.client.Resource(tenantGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("tenants: list tenants: %w", err)
	}

	s := buildSnapshot(list)
	s.backends = defaultBackends()

	// The stack says which backend each pillar runs. Reading it is advisory: a
	// permissions gap must not become an outage, so the caller keeps the last answer.
	stacks, err := f.client.Resource(telemetryStackGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		log.Printf("WARN: cannot read telemetrystacks, keeping the last known backends: %v", err)
		return s, nil
	}

	s.backends = backendsFromStacks(stacks)
	s.backendsKnown = true
	return s, nil
}

// defaultBackends is what this stack ran before backends were selectable.
func defaultBackends() Backends {
	return Backends{Metrics: "thanos", Logs: "clickhouse", Traces: "clickhouse"}
}

// backendsFromStacks reads the per-pillar backends off the first stack, defaulting
// to what it ran before backends were selectable.
func backendsFromStacks(list *unstructured.UnstructuredList) Backends {
	b := defaultBackends()
	if list == nil || len(list.Items) == 0 {
		return b
	}
	obj := list.Items[0].Object
	if v, ok, _ := unstructured.NestedString(obj, "spec", "metrics", "backend"); ok && v != "" {
		b.Metrics = strings.ToLower(v)
	}
	if v, ok, _ := unstructured.NestedString(obj, "spec", "metrics", "victoriaMetrics", "deploymentMode"); ok && v != "" {
		b.MetricsMode = strings.ToLower(v)
	}
	if v, ok, _ := unstructured.NestedString(obj, "spec", "logs", "backend"); ok && v != "" {
		b.Logs = strings.ToLower(v)
	}
	if v, ok, _ := unstructured.NestedString(obj, "spec", "traces", "backend"); ok && v != "" {
		b.Traces = strings.ToLower(v)
	}
	return b
}

func buildSnapshot(list *unstructured.UnstructuredList) *snapshot {
	s := &snapshot{
		owners:        make(map[string]struct{}),
		clusters:      make(map[string]struct{}),
		tenantNames:   make(map[string]string),
		routes:        make(map[string]Route),
		clusterClaims: make(map[string]ClusterClaims),
	}
	for _, item := range list.Items {
		tenantID, _, _ := unstructured.NestedString(item.Object, "spec", "tenantID")
		tenantName, _, _ := unstructured.NestedString(item.Object, "spec", "tenantName")
		if tenantID != "" && tenantName != "" {
			s.tenantNames[tenantName] = tenantID
		}
		if tenantID != "" {
			if route, ok := routeFromStatus(item.Object); ok {
				s.routes[tenantID] = route
			}
		}

		// What the cluster's certificate would have carried, for callers that
		// hold no per-cluster certificate.
		if strings.HasPrefix(tenantID, "cluster:") {
			owner, _, _ := unstructured.NestedString(item.Object, "spec", "owner")
			enableTenant, _, _ := unstructured.NestedBool(item.Object, "spec", "enableTenant")
			if owner != "" {
				s.clusterClaims[strings.TrimPrefix(tenantID, "cluster:")] = ClusterClaims{
					Owner:        owner,
					EnableTenant: enableTenant,
				}
			}
		}

		revoked, _, _ := unstructured.NestedBool(item.Object, "spec", "revoked")
		if !revoked || tenantID == "" {
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

// routeFromStatus reads the coordinates the tenant operator recorded. A tenant with
// no accountID yet is skipped rather than stored as account 0.
func routeFromStatus(obj map[string]interface{}) (Route, bool) {
	accountID, found, err := unstructured.NestedInt64(obj, "status", "accountID")
	if err != nil || !found || accountID <= 0 {
		return Route{}, false
	}
	projectID, _, _ := unstructured.NestedInt64(obj, "status", "projectID")

	return Route{
		AccountID: accountID,
		ProjectID: projectID,
		Metrics:   endpointFromStatus(obj, "metrics"),
		Logs:      endpointFromStatus(obj, "logs"),
		Traces:    endpointFromStatus(obj, "traces"),
	}, true
}

func endpointFromStatus(obj map[string]interface{}, pillar string) Endpoint {
	instance, _, _ := unstructured.NestedString(obj, "status", pillar, "instance")
	read, _, _ := unstructured.NestedString(obj, "status", pillar, "readURL")
	write, _, _ := unstructured.NestedString(obj, "status", pillar, "writeURL")
	return Endpoint{Instance: instance, ReadURL: read, WriteURL: write}
}
