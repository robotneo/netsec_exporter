package firewall

import (
	"netsec_exporter/collectors/h3c/client"
	"netsec_exporter/core"
)

func Collect(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return []core.Metric{}, nil
}

