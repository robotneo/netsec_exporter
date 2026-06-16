package firewall

import (
	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

// CollectHAMetrics 承载 HA/集群类指标。
func CollectHAMetrics(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return nil, nil
}
