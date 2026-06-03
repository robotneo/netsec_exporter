package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectHAStatus(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/system/ha", dev.Host, sess.Namespace)

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
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/system/ha", dev.Host)
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
		return nil, fmt.Errorf("system/ha api status code: %d", resp.StatusCode)
	}

	var hr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			HAConfig struct {
				HAEnable bool   `json:"haEnable"`
				Mode     string `json:"mode"`
			} `json:"haConfig"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return nil, err
	}
	if hr.Code != 0 {
		return nil, fmt.Errorf("system/ha failed: code=%d message=%s", hr.Code, hr.Message)
	}

	enabled := 0.0
	if hr.Data.HAConfig.HAEnable {
		enabled = 1
	}

	mode := 0.0
	switch hr.Data.HAConfig.Mode {
	case "ACTIVE-ACTIVE":
		mode = 1
	case "ACTIVE-PASSIVE":
		mode = 2
	case "MIRROR":
		mode = 3
	}

	labels := map[string]string{
		"device": dev.Name,
		"vendor": dev.Vendor,
		"type":   dev.Type,
	}

	return []core.Metric{
		{
			Name:   "netsec_ha_enabled",
			Value:  enabled,
			Labels: labels,
		},
		{
			Name:   "netsec_ha_mode",
			Value:  mode,
			Labels: labels,
		},
	}, nil
}
