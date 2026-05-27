package collectors

import (
	"netsec_exporter/core"
)

// H3C 华三设备采集示例
// 目前仅作为模板，暂不启用实际采集逻辑
type H3C struct{}

func (c *H3C) Name() string {
	return "h3c"
}

func (c *H3C) Supported(dev core.Device) bool {
	return dev.Vendor == "h3c"
}

func (c *H3C) Collect(dev core.Device) ([]core.Metric, error) {
	// TODO: 后续在此实现 H3C 的 SNMP 或 REST API 采集逻辑
	// 示例：返回一个空列表或模拟数据
	var metrics []core.Metric

	/* 模拟数据示例：
	metrics = append(metrics, core.Metric{
		Name:  "netsec_iplink_status",
		Value: 1,
		Labels: map[string]string{
			"name":        "TestLink",
			"interface":   "GE1/0/1",
			"destination": "8.8.8.8",
		},
	})
	*/

	return metrics, nil
}
