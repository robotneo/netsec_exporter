package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectMemoryUsagePercent(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/memoryusage", dev.Host, sess.Namespace)

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
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/memoryusage", dev.Host)
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
		return nil, fmt.Errorf("memoryusage api status code: %d", resp.StatusCode)
	}

	var mr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			MemoryUsage float64 `json:"memoryUsage"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		return nil, err
	}
	if mr.Code != 0 {
		return nil, fmt.Errorf("memoryusage failed: code=%d message=%s", mr.Code, mr.Message)
	}

	return []core.Metric{
		{
			Name:  "netsec_system_memory_usage_percent",
			Value: mr.Data.MemoryUsage,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"type":        dev.Type,
			},
		},
	}, nil
}
