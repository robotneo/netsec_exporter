package firewall

import (
	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

// CollectPolicyMetrics 承载策略与对象类指标。
func CollectPolicyMetrics(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return nil, nil
}
