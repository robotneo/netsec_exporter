package collectors

import "netsec_exporter/core"

type QiAnXin struct{}

func (c *QiAnXin) Name() string {
	return "qianxin"
}

func (c *QiAnXin) Supported(dev core.Device) bool {
	return dev.Vendor == "qianxin"
}

func (c *QiAnXin) Collect(dev core.Device) ([]core.Metric, error) {
	return []core.Metric{}, nil
}

