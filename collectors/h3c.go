package collectors

import (
	"fmt"
	"netsec_exporter/core"
	"sync"
	"time"

	h3cclient "netsec_exporter/collectors/h3c/client"
	h3cfw "netsec_exporter/collectors/h3c/firewall"
)

type H3C struct {
	once   sync.Once
	client *h3cclient.Client
}

func (c *H3C) Name() string {
	return "h3c"
}

func (c *H3C) Supported(dev core.Device) bool {
	return dev.Vendor == "h3c"
}

func (c *H3C) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		return h3cfw.Collect(c.client, dev)
	default:
		return nil, fmt.Errorf("unsupported device type for h3c: %s", dev.Type)
	}
}

func (c *H3C) init() {
	c.once.Do(func() {
		c.client = h3cclient.New(10*time.Second, true)
	})
}
