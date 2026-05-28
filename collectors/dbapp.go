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
}

func (c *DBAPP) init() {
	c.once.Do(func() {
		c.client = dbappclient.New(10*time.Second, true)
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
		return dbappfw.CollectIPLinkStatus(c.client, dev)
	case "dastgfw":
		return dbappfw.CollectIPLinkStatus(c.client, dev)
	default:
		return nil, fmt.Errorf("unsupported device type for dbapp: %s", dev.Type)
	}
}
