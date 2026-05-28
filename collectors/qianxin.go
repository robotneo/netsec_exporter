package collectors

import (
	"fmt"
	"sync"
	"time"

	qianxinclient "netsec_exporter/collectors/qianxin/client"
	qianxinfw "netsec_exporter/collectors/qianxin/firewall"
	"netsec_exporter/core"
)

type QiAnXin struct {
	once   sync.Once
	client *qianxinclient.Client
}

func (c *QiAnXin) init() {
	c.once.Do(func() {
		c.client = qianxinclient.New(10*time.Second, true)
	})
}

func (c *QiAnXin) Name() string {
	return "qianxin"
}

func (c *QiAnXin) Supported(dev core.Device) bool {
	return dev.Vendor == "qianxin"
}

func (c *QiAnXin) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		return qianxinfw.Collect(c.client, dev)
	default:
		return nil, fmt.Errorf("unsupported device type for qianxin: %s", dev.Type)
	}
}
