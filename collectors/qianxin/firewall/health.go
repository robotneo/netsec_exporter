package firewall

import (
	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

// CollectHealthMetrics 承载风扇、电源、温度等健康类指标。
func CollectHealthMetrics(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return nil, nil
}
