package collectors

import (
	"fmt"
	"sync"
	"time"

	fortinetclient "netsec_exporter/collectors/fortinet/client"
	fortinetfw "netsec_exporter/collectors/fortinet/firewall"
	"netsec_exporter/core"
)

type Fortinet struct {
	once   sync.Once
	client *fortinetclient.Client
}

func (c *Fortinet) init() {
	c.once.Do(func() {
		c.client = fortinetclient.New(10*time.Second, true)
	})
}

func (c *Fortinet) Name() string {
	return "fortinet"
}

func (c *Fortinet) Supported(dev core.Device) bool {
	return dev.Vendor == "fortinet"
}

func (c *Fortinet) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		return fortinetfw.Collect(c.client, dev)
	default:
		return nil, fmt.Errorf("unsupported device type for fortinet: %s", dev.Type)
	}
}
