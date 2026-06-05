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

	Timeout            time.Duration
	InsecureSkipVerify bool
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
		timeout := c.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		c.client = sangforclient.New(timeout, c.InsecureSkipVerify)
		c.sm = sangforclient.NewSessionManager(c.client, 10*time.Minute)
	})
}

func (c *Sangfor) collectFirewallV1(dev core.Device) ([]core.Metric, error) {
	sess, err := c.sm.GetOrLogin(dev)
	if err != nil {
		return nil, err
	}

	cpuMetrics, err := sangforfw.CollectCPUCurrentPercent(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		cpuMetrics, err = sangforfw.CollectCPUCurrentPercent(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	memMetrics, err := sangforfw.CollectMemoryUsagePercent(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		memMetrics, err = sangforfw.CollectMemoryUsagePercent(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	diskMetrics, err := sangforfw.CollectDiskUsagePercent(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		diskMetrics, err = sangforfw.CollectDiskUsagePercent(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	concurrentMetrics, err := sangforfw.CollectConcurrentSessions(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		concurrentMetrics, err = sangforfw.CollectConcurrentSessions(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	newSessionMetrics, err := sangforfw.CollectNewSessions(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		newSessionMetrics, err = sangforfw.CollectNewSessions(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	trafficMetrics, err := sangforfw.CollectInterfaceTrafficBits(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		trafficMetrics, err = sangforfw.CollectInterfaceTrafficBits(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	interfaceMetrics, err := sangforfw.CollectInterfaces(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		interfaceMetrics, err = sangforfw.CollectInterfaces(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	haMetrics, err := sangforfw.CollectHAStatus(c.client, sess, dev)
	if err != nil {
		c.sm.Invalidate(dev.Host)
		sess, err = c.sm.GetOrLogin(dev)
		if err != nil {
			return nil, err
		}
		haMetrics, err = sangforfw.CollectHAStatus(c.client, sess, dev)
		if err != nil {
			return nil, err
		}
	}

	metrics := append([]core.Metric{}, cpuMetrics...)
	metrics = append(metrics, memMetrics...)
	metrics = append(metrics, diskMetrics...)
	metrics = append(metrics, concurrentMetrics...)
	metrics = append(metrics, newSessionMetrics...)
	metrics = append(metrics, trafficMetrics...)
	metrics = append(metrics, interfaceMetrics...)
	metrics = append(metrics, haMetrics...)
	return metrics, nil
}
