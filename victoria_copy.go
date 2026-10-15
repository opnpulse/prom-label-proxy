package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus-community/prom-label-proxy/tenants"
)

const maxCopyBody = 64 << 20

var copyClient = &http.Client{Timeout: 30 * time.Second}

// groupByClientOrg picks the series whose namespace names another tenant.
func groupByClientOrg(series []prompb.TimeSeries, tenant string, resolve func(string) (string, bool)) map[string][]prompb.TimeSeries {
	out := map[string][]prompb.TimeSeries{}
	for _, ts := range series {
		for _, l := range ts.Labels {
			if l.Name != "namespace" {
				continue
			}
			if id, ok := resolve(l.Value); ok && id != tenant {
				out[id] = append(out[id], ts)
			}
			break
		}
	}
	return out
}

// copyToClientOrgs also writes series of a client org's namespace to that org's
// account, so its reads find cluster level series such as panopticon's.
func copyToClientOrgs(ctx context.Context, body []byte, tenant string, cache *tenants.Cache, standalone bool) error {
	raw, err := snappy.Decode(nil, body)
	if err != nil {
		return nil // the primary write reports a bad payload
	}
	var wr prompb.WriteRequest
	if err := wr.Unmarshal(raw); err != nil {
		return nil
	}
	resolve := func(ns string) (string, bool) {
		id, ok := cache.ResolveTenantID(ns)
		return id, ok && !cache.IsTenantRevoked(id)
	}
	for id, series := range groupByClientOrg(wr.Timeseries, tenant, resolve) {
		route, ok := cache.Route(id)
		if !ok || !route.Addressable() || route.Metrics.WriteURL == "" {
			continue
		}
		payload, err := (&prompb.WriteRequest{Timeseries: series}).Marshal()
		if err != nil {
			return err
		}
		u := strings.TrimRight(route.Metrics.WriteURL, "/")
		if standalone {
			q := url.Values{"extra_label": {
				fmt.Sprintf("%s=%d", injectproxy.VictoriaAccountLabel, route.AccountID),
				fmt.Sprintf("%s=%d", injectproxy.VictoriaProjectLabel, route.ProjectID),
			}}
			u += injectproxy.VictoriaSingleWritePath + "?" + q.Encode()
		} else {
			u += injectproxy.VictoriaWritePath(route.AccountID, route.ProjectID)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(snappy.Encode(nil, payload)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.Header.Set("Content-Encoding", "snappy")
		req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
		resp, err := copyClient.Do(req)
		if err != nil {
			return fmt.Errorf("copy to %s: %w", id, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("copy to %s: status %d", id, resp.StatusCode)
		}
	}
	return nil
}
