package collectors

import (
	"fmt"
	"sync"
	"time"

	dbappclient "netsec_exporter/collectors/dbapp/client"
	dbappfw "netsec_exporter/collectors/dbapp/firewall"
	"netsec_exporter/core"
)

type DBAPP struct {
	once   sync.Once
	client *dbappclient.Client

	Timeout            time.Duration
	InsecureSkipVerify bool
}

func (c *DBAPP) init() {
	c.once.Do(func() {
		timeout := c.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		c.client = dbappclient.New(timeout, c.InsecureSkipVerify)
	})
}

func (c *DBAPP) Name() string {
	return "dbapp"
}

func (c *DBAPP) Supported(dev core.Device) bool {
	return dev.Vendor == "dbapp"
}

type APIResp struct {
	Vals []struct {
		Name        string `json:"name"`
		Interface   string `json:"interface"`
		Destination string `json:"destination"`
		Status      bool   `json:"status"`
	} `json:"vals"`
}

func (c *DBAPP) Collect(dev core.Device) ([]core.Metric, error) {
	c.init()

	switch dev.Type {
	case "firewall":
		iplinkMetrics, err := dbappfw.CollectIPLinkStatus(c.client, dev)
		if err != nil {
			return nil, err
		}

		ifMetrics, err := dbappfw.CollectInterfaces(c.client, dev)
		if err != nil {
			return iplinkMetrics, nil
		}

		metrics := append([]core.Metric{}, iplinkMetrics...)
		metrics = append(metrics, ifMetrics...)
		cpuMetrics, err := dbappfw.CollectCPUUsagePercentSNMP(dev, c.Timeout)
		if err == nil {
			metrics = append(metrics, cpuMetrics...)
		}
		memMetrics, err := dbappfw.CollectMemoryUsagePercentSNMP(dev, c.Timeout)
		if err == nil {
			metrics = append(metrics, memMetrics...)
		}
		diskMetrics, err := dbappfw.CollectDiskUsagePercentSNMP(dev, c.Timeout)
		if err == nil {
			metrics = append(metrics, diskMetrics...)
		}
		return metrics, nil
	case "dastgfw":
		iplinkMetrics, err := dbappfw.CollectIPLinkStatus(c.client, dev)
		if err != nil {
			return nil, err
		}

		ifMetrics, err := dbappfw.CollectInterfaces(c.client, dev)
		if err != nil {
			return iplinkMetrics, nil
		}

		metrics := append([]core.Metric{}, iplinkMetrics...)
		metrics = append(metrics, ifMetrics...)
		cpuMetrics, err := dbappfw.CollectCPUUsagePercentSNMP(dev, c.Timeout)
		if err == nil {
			metrics = append(metrics, cpuMetrics...)
		}
		memMetrics, err := dbappfw.CollectMemoryUsagePercentSNMP(dev, c.Timeout)
		if err == nil {
			metrics = append(metrics, memMetrics...)
		}
		diskMetrics, err := dbappfw.CollectDiskUsagePercentSNMP(dev, c.Timeout)
		if err == nil {
			metrics = append(metrics, diskMetrics...)
		}
		return metrics, nil
	default:
		return nil, fmt.Errorf("unsupported device type for dbapp: %s", dev.Type)
	}
}
