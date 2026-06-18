package firewall

import (
	"context"
	"fmt"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectSessionMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	metrics := []core.Metric{}
	var lastErr error

	if v, err := fetchLatestConnectionMetric(context.Background(), c, sess, dev, "sessions_new"); err == nil {
		metrics = append(metrics, core.Metric{
			Name:  "netsec_sessions_new_per_second",
			Value: v,
		})
	} else {
		lastErr = err
	}

	if v, err := fetchLatestConnectionMetric(context.Background(), c, sess, dev, "sessions"); err == nil {
		metrics = append(metrics, core.Metric{
			Name:  "netsec_session_active_current",
			Value: v,
		})
	} else {
		lastErr = err
	}

	if len(metrics) > 0 {
		return metrics, nil
	}
	return nil, lastErr
}

func fetchLatestConnectionMetric(ctx context.Context, c *client.Client, sess client.Session, dev core.Device, orderBy string) (float64, error) {
	req := []client.RESTRequest{
		{
			Head: client.RESTHead{
				Function:  "get_connection_monitor",
				Module:    "statistics",
				PageIndex: 1,
				PageSize:  2000,
			},
			Body: client.RESTBody{
				Data: map[string]any{
					"time":     "last-15-minutes",
					"order_by": orderBy,
					"map":      "trend_line",
				},
			},
		},
	}

	var resp qianxinConnectionMonitorResponse
	if err := c.PostREST(ctx, dev, sess, req, &resp); err != nil {
		return 0, err
	}
	if err := client.EnsureRESTOK("get_connection_monitor", resp.Head); err != nil {
		return 0, err
	}

	v, ok := resp.latestByOrderBy(orderBy)
	if !ok {
		return 0, fmt.Errorf("%s not found in response", orderBy)
	}
	return v, nil
}

type qianxinConnectionMonitorResponse struct {
	Head client.RESTResponseHead `json:"head"`
	Data struct {
		Series []struct {
			SessionsNew []float64 `json:"sessions_new"`
			Sessions    []float64 `json:"sessions"`
		} `json:"series"`
	} `json:"data"`
}

func (r qianxinConnectionMonitorResponse) latestByOrderBy(orderBy string) (float64, bool) {
	for _, s := range r.Data.Series {
		switch orderBy {
		case "sessions_new":
			if len(s.SessionsNew) == 0 {
				continue
			}
			return s.SessionsNew[len(s.SessionsNew)-1], true
		case "sessions":
			if len(s.Sessions) == 0 {
				continue
			}
			return s.Sessions[len(s.Sessions)-1], true
		}
	}
	return 0, false
}
