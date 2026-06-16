package firewall

import (
	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

// CollectLogMetrics 承载日志与告警类指标。
func CollectLogMetrics(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return nil, nil
}
