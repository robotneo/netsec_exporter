package collectors

import (
	"fmt"
	"netsec_exporter/core"
	"sync"
	"time"

	huaweiclient "netsec_exporter/collectors/huawei/client"
	huaweifw "netsec_exporter/collectors/huawei/firewall"
)

type Huawei struct {
	once   sync.Once
	client *huaweiclient.Client
}

func (c *Huawei) init() {
	c.once.Do(func() {
		c.client = huaweiclient.New(10*time.Second, true)
	})
}

func (c *Huawei) Name() string {
	return "huawei"
}

func (c *Huawei) Supported(dev core.Device) bool {
	return dev.Vendor == "huawei"
}

func (c *Huawei) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		return huaweifw.Collect(c.client, dev)
	default:
		return nil, fmt.Errorf("unsupported device type for huawei: %s", dev.Type)
	}
}
