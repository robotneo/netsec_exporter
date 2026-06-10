package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectPowerStatus(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/powerInfo", dev.Host, sess.Namespace)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AuthorizationToken", sess.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/powerInfo", dev.Host)
		req, err = http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("AuthorizationToken", sess.Token)
		resp, err = c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("powerInfo api status code: %d", resp.StatusCode)
	}

	var pr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	if pr.Code != 0 {
		return nil, fmt.Errorf("powerInfo failed: code=%d message=%s", pr.Code, pr.Message)
	}

	metrics := make([]core.Metric, 0, len(pr.Data))
	for _, power := range pr.Data {
		value := 0.0
		switch strings.TrimSpace(power.State) {
		case "Normal":
			value = 1
		case "Abnormal":
			value = 0
		default:
			value = 0
		}

		labels := map[string]string{
			"device_name": dev.Name,
			"vendor":      dev.Vendor,
			"role":        dev.Type,
			"sensor_name": strings.TrimSpace(power.Name),
		}

		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_power_status",
			Value:  value,
			Labels: labels,
		})
	}

	return metrics, nil
}
