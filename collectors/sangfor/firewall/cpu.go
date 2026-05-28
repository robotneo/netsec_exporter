package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectCPUCurrentPercent(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/cpuusage", dev.Host, sess.Namespace)

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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cpuusage api status code: %d", resp.StatusCode)
	}

	var cr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			CPUCurrent string `json:"cpuCurrent"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}
	if cr.Code != 0 {
		return nil, fmt.Errorf("cpuusage failed: code=%d message=%s", cr.Code, cr.Message)
	}

	var cpu float64
	if _, err := fmt.Sscanf(cr.Data.CPUCurrent, "%f", &cpu); err != nil {
		return nil, fmt.Errorf("cpuusage parse failed")
	}

	return []core.Metric{
		{
			Name:  "netsec_cpu_current_percent",
			Value: cpu,
			Labels: map[string]string{
				"device": dev.Name,
				"vendor": dev.Vendor,
				"type":   dev.Type,
			},
		},
	}, nil
}

