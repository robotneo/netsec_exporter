package firewall

import (
	"context"
	"strconv"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectHAMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemInfo(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}

	ha := strings.TrimSpace(resp.Data.HA)
	if ha == "" {
		return nil, nil
	}

	labels := map[string]string{
		"ha": ha,
	}
	if hostname := strings.TrimSpace(resp.Data.Hostname); hostname != "" {
		labels["hostname"] = hostname
	}

	return []core.Metric{
		{
			Name:   "netsec_ha_status",
			Value:  parseHAStatusValue(ha),
			Labels: labels,
		},
	}, nil
}

func parseHAStatusValue(ha string) float64 {
	ha = strings.TrimSpace(ha)
	if ha == "" {
		return 0
	}
	prefix := ha
	if idx := strings.Index(prefix, ":"); idx >= 0 {
		prefix = prefix[:idx]
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(prefix), 64); err == nil {
		return v
	}
	return 1
}
