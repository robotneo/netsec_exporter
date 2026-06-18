package firewall

import (
	"context"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectHealthMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemResource(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}

	var metrics []core.Metric
	if ms, err := buildFanMetrics(resp); err == nil {
		metrics = append(metrics, ms...)
	}
	if ms, err := buildPowerMetrics(resp); err == nil {
		metrics = append(metrics, ms...)
	}
	return metrics, nil
}
