package firewall

import (
	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

// CollectSystemMetrics 承载系统类指标。
func CollectSystemMetrics(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return nil, nil
}
