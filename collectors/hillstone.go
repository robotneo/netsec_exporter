package collectors

import (
	"fmt"
	"sync"
	"time"

	hillstoneclient "netsec_exporter/collectors/hillstone/client"
	hillstonefw "netsec_exporter/collectors/hillstone/firewall"
	"netsec_exporter/core"
)

type Hillstone struct {
	once   sync.Once
	client *hillstoneclient.Client
}

func (c *Hillstone) init() {
	c.once.Do(func() {
		c.client = hillstoneclient.New(10*time.Second, true)
	})
}

func (c *Hillstone) Name() string {
	return "hillstone"
}

func (c *Hillstone) Supported(dev core.Device) bool {
	return dev.Vendor == "hillstone"
}

func (c *Hillstone) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		return hillstonefw.Collect(c.client, dev)
	default:
		return nil, fmt.Errorf("unsupported device type for hillstone: %s", dev.Type)
	}
}
