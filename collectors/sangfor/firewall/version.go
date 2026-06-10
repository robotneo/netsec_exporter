package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectVersionInfo(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/systemversion", dev.Host, sess.Namespace)

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
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/systemversion", dev.Host)
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
		return nil, fmt.Errorf("systemversion api status code: %d", resp.StatusCode)
	}

	var sr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Full string `json:"full"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, err
	}
	if sr.Code != 0 {
		return nil, fmt.Errorf("systemversion failed: code=%d message=%s", sr.Code, sr.Message)
	}

	labels := map[string]string{
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"type":        dev.Type,
	}
	if sr.Data.Full != "" {
		labels["version"] = sr.Data.Full
	}

	return []core.Metric{
		{
			Name:   "netsec_system_version_info",
			Value:  1,
			Labels: labels,
		},
	}, nil
}

func VersionUnavailableMetric(dev core.Device) []core.Metric {
	return []core.Metric{
		{
			Name:  "netsec_system_version_info",
			Value: 0,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"type":        dev.Type,
			},
		},
	}
}
