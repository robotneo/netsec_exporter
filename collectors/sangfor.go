package collectors

import (
	"context"
	"fmt"
	"sync"
	"time"

	sangforclient "netsec_exporter/collectors/sangfor/client"
	sangforfw "netsec_exporter/collectors/sangfor/firewall"
	sangforhci "netsec_exporter/collectors/sangfor/hci"
	"netsec_exporter/core"
)

type Sangfor struct {
	once   sync.Once
	client *sangforclient.Client
	sm     *sangforclient.SessionManager

	hciMu      sync.Mutex
	hciBundles map[string]hciBundle

	Timeout            time.Duration
	InsecureSkipVerify bool
}

type hciBundle struct {
	client *sangforclient.HCIClient
	sm     *sangforclient.HCISessionManager
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
	case "hci":
		return c.collectHCI(dev)
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
		c.hciBundles = map[string]hciBundle{}
	})
}

func (c *Sangfor) getHCIBundle(host string) hciBundle {
	c.hciMu.Lock()
	defer c.hciMu.Unlock()

	if b, ok := c.hciBundles[host]; ok {
		return b
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	hc := sangforclient.NewHCIClient(host, timeout, c.InsecureSkipVerify)
	b := hciBundle{
		client: hc,
		sm:     sangforclient.NewHCISessionManager(hc),
	}
	c.hciBundles[host] = b
	return b
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

func (c *Sangfor) collectHCI(dev core.Device) ([]core.Metric, error) {
	b := c.getHCIBundle(dev.Host)

	var sess sangforclient.HCISession
	if dev.Token != "" {
		sess = sangforhci.TokenSession(dev.Token)
	} else {
		if dev.Username == "" || dev.Password == "" {
			return nil, fmt.Errorf("missing username/password for HCI")
		}
		s, err := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
		if err != nil {
			return nil, err
		}
		sess = s
	}

	overviewMetrics, err := sangforhci.CollectOverviewMetrics(b.client, sess, dev)
	if err != nil {
		if dev.Token == "" {
			b.sm.Invalidate()
			s, e := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
			if e != nil {
				return nil, e
			}
			sess = s
			overviewMetrics, err = sangforhci.CollectOverviewMetrics(b.client, sess, dev)
		}
		if err != nil {
			return nil, err
		}
	}

	azHostMetrics, err := sangforhci.CollectAZAndHostMetrics(b.client, sess, dev)
	if err != nil {
		if dev.Token == "" {
			b.sm.Invalidate()
			s, e := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
			if e != nil {
				return nil, e
			}
			sess = s
			azHostMetrics, err = sangforhci.CollectAZAndHostMetrics(b.client, sess, dev)
		}
		if err != nil {
			return nil, err
		}
	}

	vmMetrics, err := sangforhci.CollectVMMetrics(b.client, sess, dev)
	if err != nil {
		if dev.Token == "" {
			b.sm.Invalidate()
			s, e := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
			if e != nil {
				return nil, e
			}
			sess = s
			vmMetrics, err = sangforhci.CollectVMMetrics(b.client, sess, dev)
		}
		if err != nil {
			return nil, err
		}
	}

	storageMetrics, err := sangforhci.CollectStorageMetrics(b.client, sess, dev)
	if err != nil {
		if dev.Token == "" {
			b.sm.Invalidate()
			s, e := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
			if e != nil {
				return nil, e
			}
			sess = s
			storageMetrics, err = sangforhci.CollectStorageMetrics(b.client, sess, dev)
		}
		if err != nil {
			return nil, err
		}
	}

	networkMetrics, err := sangforhci.CollectNetworkMetrics(b.client, sess, dev)
	if err != nil {
		if dev.Token == "" {
			b.sm.Invalidate()
			s, e := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
			if e != nil {
				return nil, e
			}
			sess = s
			networkMetrics, err = sangforhci.CollectNetworkMetrics(b.client, sess, dev)
		}
		if err != nil {
			return nil, err
		}
	}

	metrics := append([]core.Metric{}, overviewMetrics...)
	metrics = append(metrics, azHostMetrics...)
	metrics = append(metrics, vmMetrics...)
	metrics = append(metrics, storageMetrics...)
	metrics = append(metrics, networkMetrics...)
	return metrics, nil
}
