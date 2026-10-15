package main

import (
	"testing"

	"github.com/prometheus/prometheus/prompb"
)

func TestGroupByClientOrg(t *testing.T) {
	ids := map[string]string{"client-org-2": "ace.user.10", "appscode": "ace.user.4"}
	resolve := func(ns string) (string, bool) { id, ok := ids[ns]; return id, ok }
	series := func(ns string) prompb.TimeSeries {
		return prompb.TimeSeries{Labels: []prompb.Label{{Name: "__name__", Value: "m"}, {Name: "namespace", Value: ns}}}
	}
	in := []prompb.TimeSeries{series("client-org-2"), series("kubeops"), series("appscode"), {Labels: []prompb.Label{{Name: "__name__", Value: "n"}}}}

	got := groupByClientOrg(in, "ace.user.4", resolve)
	if len(got) != 1 || len(got["ace.user.10"]) != 1 {
		t.Fatalf("want only client-org-2 copied, got %v", got)
	}
	if got := groupByClientOrg(in, "ace.user.10", resolve); len(got["ace.user.10"]) != 0 {
		t.Fatalf("a tenant's own series must not be copied back, got %v", got)
	}
}
