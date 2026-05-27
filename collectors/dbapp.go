package collectors

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"netsec_exporter/core"
)

type DBAPP struct {
	client *http.Client
	once   sync.Once
}

func (c *DBAPP) init() {
	c.once.Do(func() {
		c.client = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
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

	// Handle different device types for DBAPP
	switch dev.Type {
	case "dastgfw": // 明御防火墙
		return c.collectDastgfw(dev)
	default:
		return nil, fmt.Errorf("unsupported device type for dbapp: %s", dev.Type)
	}
}

func (c *DBAPP) collectDastgfw(dev core.Device) ([]core.Metric, error) {
	url := fmt.Sprintf("https://%s/api/v1/iplink", dev.Host)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+dev.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api status code: %d", resp.StatusCode)
	}

	var r APIResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}

	var metrics []core.Metric
	for _, v := range r.Vals {
		val := 0.0
		if v.Status {
			val = 1
		}

		metrics = append(metrics, core.Metric{
			Name:  "netsec_iplink_status",
			Value: val,
			Labels: map[string]string{
				"name":        v.Name,
				"interface":   v.Interface,
				"destination": v.Destination,
			},
		})
	}

	return metrics, nil
}
