package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectDiskUsagePercent(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/diskusage", dev.Host, sess.Namespace)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AuthorizationToken", sess.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/diskusage", dev.Host)
		req, err = http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("AuthorizationToken", sess.Token)

		resp, err = c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("diskusage api status code: %d", resp.StatusCode)
	}

	var dr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			DiskUsage float64 `json:"diskUsage"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dr); err != nil {
		return nil, err
	}
	if dr.Code != 0 {
		return nil, fmt.Errorf("diskusage failed: code=%d message=%s", dr.Code, dr.Message)
	}

	return []core.Metric{
		{
			Name:  "netsec_disk_usage_percent",
			Value: dr.Data.DiskUsage,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"type":        dev.Type,
			},
		},
	}, nil
}
