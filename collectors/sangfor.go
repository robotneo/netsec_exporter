package collectors

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	sangforac "netsec_exporter/collectors/sangfor/ac"
	sangforad "netsec_exporter/collectors/sangfor/ad"
	sangforclient "netsec_exporter/collectors/sangfor/client"
	sangforfw "netsec_exporter/collectors/sangfor/firewall"
	sangforhci "netsec_exporter/collectors/sangfor/hci"
	"netsec_exporter/core"
)

type Sangfor struct {
	once   sync.Once
	client *sangforclient.Client
	sm     *sangforclient.SessionManager

	acMu      sync.Mutex
	acClients map[string]*sangforclient.ACClient

	hciMu      sync.Mutex
	hciBundles map[string]hciBundle

	Timeout            time.Duration
	InsecureSkipVerify bool
}

type hciBundle struct {
	client *sangforclient.HCIClient
	sm     *sangforclient.HCISessionManager
}

type metricCollector func() ([]core.Metric, error)
type firewallMetricCollector func(sangforclient.Session) ([]core.Metric, error)
type hciMetricCollector func(sangforclient.HCISession) ([]core.Metric, error)

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
	case "ac":
		return c.collectAC(dev)
	case "ad":
		return c.collectAD(dev)
	case "hci":
		return c.collectHCI(dev)
	default:
		return nil, fmt.Errorf("unsupported device type for sangfor: %s", dev.Type)
	}
}

func collectWithRetry(collect metricCollector) ([]core.Metric, error) {
	metrics, err := collect()
	if err == nil {
		return metrics, nil
	}

	metrics, err = collect()
	if err != nil {
		return nil, err
	}
	return metrics, nil
}

func mergeMetricGroups(groups ...[]core.Metric) []core.Metric {
	total := 0
	for _, group := range groups {
		total += len(group)
	}

	metrics := make([]core.Metric, 0, total)
	for _, group := range groups {
		metrics = append(metrics, group...)
	}
	return metrics
}

func (c *Sangfor) collectFirewallWithRelogin(dev core.Device, sess *sangforclient.Session, collect firewallMetricCollector) ([]core.Metric, error) {
	metrics, err := collect(*sess)
	if err == nil {
		return metrics, nil
	}

	c.sm.Invalidate(dev.Host)

	refreshed, err := c.sm.GetOrLogin(dev)
	if err != nil {
		return nil, err
	}

	*sess = refreshed
	return collect(*sess)
}

func (c *Sangfor) getHCISession(b hciBundle, dev core.Device) (sangforclient.HCISession, error) {
	if dev.Token != "" {
		return sangforhci.TokenSession(dev.Token), nil
	}
	if dev.Username == "" || dev.Password == "" {
		return sangforclient.HCISession{}, fmt.Errorf("missing username/password for HCI")
	}
	return b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
}

func (c *Sangfor) collectHCIWithRetry(b hciBundle, dev core.Device, sess *sangforclient.HCISession, collect hciMetricCollector) ([]core.Metric, error) {
	metrics, err := collect(*sess)
	if err == nil || dev.Token != "" {
		return metrics, err
	}

	b.sm.Invalidate()

	refreshed, err := b.sm.GetOrLogin(context.Background(), dev.Username, dev.Password)
	if err != nil {
		return nil, err
	}

	*sess = refreshed
	return collect(*sess)
}

func (c *Sangfor) collectAD(dev core.Device) ([]core.Metric, error) {
	systemMetrics, err := collectWithRetry(func() ([]core.Metric, error) {
		return sangforad.CollectSystemMetrics(dev)
	})
	if err != nil {
		return nil, err
	}

	sessionMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforad.CollectSessionMetrics(dev)
	})

	interfaceMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforad.CollectInterfaceMetrics(dev)
	})

	return mergeMetricGroups(systemMetrics, sessionMetrics, interfaceMetrics), nil
}

func (c *Sangfor) init() {
	c.once.Do(func() {
		timeout := c.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		c.client = sangforclient.New(timeout, c.InsecureSkipVerify)
		c.sm = sangforclient.NewSessionManager(c.client, 10*time.Minute)
		c.acClients = map[string]*sangforclient.ACClient{}
		c.hciBundles = map[string]hciBundle{}
	})
}

func (c *Sangfor) getACClient(dev core.Device) *sangforclient.ACClient {
	c.acMu.Lock()
	defer c.acMu.Unlock()

	port := dev.ACPort
	if port == 0 {
		port = 9999
	}

	key := strings.TrimSpace(dev.Host)
	if !strings.Contains(key, ":") {
		key = fmt.Sprintf("%s:%d", key, port)
	}

	if cli, ok := c.acClients[key]; ok {
		cli.SharedKey = dev.SharedKey
		return cli
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	cli := sangforclient.NewACClient(dev.Host, port, timeout, c.InsecureSkipVerify, dev.SharedKey)
	c.acClients[key] = cli
	return cli
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

	cpuMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectCPUCurrentPercent(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	memMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectMemoryUsagePercent(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	diskMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectDiskUsagePercent(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	concurrentMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectConcurrentSessions(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	newSessionMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectNewSessions(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	trafficMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectInterfaceTrafficBits(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	interfaceMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectInterfaces(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	haMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectHAStatus(c.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	systemVersionMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectVersionInfo(c.client, sess, dev)
	})
	if err != nil {
		systemVersionMetrics = sangforfw.VersionUnavailableMetric(dev)
	}

	uptimeMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectUptimeSeconds(c.client, sess, dev)
	})
	if err != nil {
		uptimeMetrics = nil
	}

	fanMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectFanStatus(c.client, sess, dev)
	})
	if err != nil {
		fanMetrics = nil
	}

	powerMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectPowerStatus(c.client, sess, dev)
	})
	if err != nil {
		powerMetrics = nil
	}

	temperatureMetrics, err := c.collectFirewallWithRelogin(dev, &sess, func(sess sangforclient.Session) ([]core.Metric, error) {
		return sangforfw.CollectTemperatureMetrics(c.client, sess, dev)
	})
	if err != nil {
		temperatureMetrics = nil
	}

	return mergeMetricGroups(
		cpuMetrics,
		memMetrics,
		diskMetrics,
		concurrentMetrics,
		newSessionMetrics,
		trafficMetrics,
		interfaceMetrics,
		haMetrics,
		systemVersionMetrics,
		uptimeMetrics,
		fanMetrics,
		powerMetrics,
		temperatureMetrics,
	), nil
}

func (c *Sangfor) collectAC(dev core.Device) ([]core.Metric, error) {
	if strings.TrimSpace(dev.SharedKey) == "" {
		return nil, fmt.Errorf("missing shared_key for sangfor ac")
	}

	ac := c.getACClient(dev)

	systemMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforac.CollectSystemMetrics(ac, dev)
	})

	sessionMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforac.CollectSessionMetrics(ac, dev)
	})

	trafficMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforac.CollectTrafficMetrics(ac, dev)
	})

	bandwidthMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforac.CollectBandwidthMetrics(ac, dev)
	})

	interfaceMetrics, _ := collectWithRetry(func() ([]core.Metric, error) {
		return sangforac.CollectInterfaceMetrics(ac, dev)
	})

	return mergeMetricGroups(systemMetrics, sessionMetrics, trafficMetrics, bandwidthMetrics, interfaceMetrics), nil
}

func (c *Sangfor) collectHCI(dev core.Device) ([]core.Metric, error) {
	b := c.getHCIBundle(dev.Host)

	sess, err := c.getHCISession(b, dev)
	if err != nil {
		return nil, err
	}

	overviewMetrics, err := c.collectHCIWithRetry(b, dev, &sess, func(sess sangforclient.HCISession) ([]core.Metric, error) {
		return sangforhci.CollectOverviewMetrics(b.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	azHostMetrics, err := c.collectHCIWithRetry(b, dev, &sess, func(sess sangforclient.HCISession) ([]core.Metric, error) {
		return sangforhci.CollectAZAndHostMetrics(b.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	vmMetrics, err := c.collectHCIWithRetry(b, dev, &sess, func(sess sangforclient.HCISession) ([]core.Metric, error) {
		return sangforhci.CollectVMMetrics(b.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	storageMetrics, err := c.collectHCIWithRetry(b, dev, &sess, func(sess sangforclient.HCISession) ([]core.Metric, error) {
		return sangforhci.CollectStorageMetrics(b.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	networkMetrics, err := c.collectHCIWithRetry(b, dev, &sess, func(sess sangforclient.HCISession) ([]core.Metric, error) {
		return sangforhci.CollectNetworkMetrics(b.client, sess, dev)
	})
	if err != nil {
		return nil, err
	}

	return mergeMetricGroups(overviewMetrics, azHostMetrics, vmMetrics, storageMetrics, networkMetrics), nil
}
