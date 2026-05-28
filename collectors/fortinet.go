package collectors

import "netsec_exporter/core"

type Fortinet struct{}

func (c *Fortinet) Name() string {
	return "fortinet"
}

func (c *Fortinet) Supported(dev core.Device) bool {
	return dev.Vendor == "fortinet"
}

func (c *Fortinet) Collect(dev core.Device) ([]core.Metric, error) {
	return []core.Metric{}, nil
}

