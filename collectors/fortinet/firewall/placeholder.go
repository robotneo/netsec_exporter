package firewall

import (
	"netsec_exporter/collectors/fortinet/client"
	"netsec_exporter/core"
)

func Collect(c *client.Client, dev core.Device) ([]core.Metric, error) {
	_ = c
	_ = dev
	return []core.Metric{
		{
			Name:   "netsec_session_max_limit",
			Value:  0,
			Labels: nil,
		},
	}, nil
}
