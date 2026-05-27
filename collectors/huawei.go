package collectors

import (
	"netsec_exporter/core"
)

// Huawei 华为设备采集示例
// 目前仅作为模板，暂不启用实际采集逻辑
type Huawei struct{}

func (c *Huawei) Name() string {
	return "huawei"
}

func (c *Huawei) Supported(dev core.Device) bool {
	return dev.Vendor == "huawei"
}

func (c *Huawei) Collect(dev core.Device) ([]core.Metric, error) {
	// TODO: 后续在此实现 Huawei 的 SNMP 或 SSH/CLI 采集逻辑
	var metrics []core.Metric
	return metrics, nil
}
