package collectors

import "netsec_exporter/core"

type Hillstone struct{}

func (c *Hillstone) Name() string {
	return "hillstone"
}

func (c *Hillstone) Supported(dev core.Device) bool {
	return dev.Vendor == "hillstone"
}

func (c *Hillstone) Collect(dev core.Device) ([]core.Metric, error) {
	return []core.Metric{}, nil
}

