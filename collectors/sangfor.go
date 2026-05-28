package collectors

import (
	"fmt"
	"sync"
	"time"

	sangforclient "netsec_exporter/collectors/sangfor/client"
	sangforfw "netsec_exporter/collectors/sangfor/firewall"
	"netsec_exporter/core"
)

type Sangfor struct {
	once   sync.Once
	client *sangforclient.Client
	sm     *sangforclient.SessionManager
}

func (c *Sangfor) Name() string {
	return "sangfor"
}

func (c *Sangfor) Supported(dev core.Device) bool {
	return dev.Vendor == "sangfor"
}

func (c *Sangfor) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		return c.collectFirewallV1(dev)
	default:
		return nil, fmt.Errorf("unsupported device type for sangfor: %s", dev.Type)
	}
}

func (c *Sangfor) init() {
	c.once.Do(func() {
		c.client = sangforclient.New(10*time.Second, true)
		c.sm = sangforclient.NewSessionManager(c.client, 10*time.Minute)
	})
}

func (c *Sangfor) collectFirewallV1(dev core.Device) ([]core.Metric, error) {
	sess, err := c.sm.GetOrLogin(dev)
	if err != nil {
		return nil, err
	}

	metrics, err := sangforfw.CollectCPUCurrentPercent(c.client, sess, dev)
	if err == nil {
		return metrics, nil
	}

	c.sm.Invalidate(dev.Host)
	sess, err = c.sm.GetOrLogin(dev)
	if err != nil {
		return nil, err
	}
	return sangforfw.CollectCPUCurrentPercent(c.client, sess, dev)
}
