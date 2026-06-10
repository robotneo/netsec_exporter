package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectTemperatureMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/tempratureInfo", dev.Host, sess.Namespace)

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
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/tempratureInfo", dev.Host)
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
		return nil, fmt.Errorf("tempratureInfo api status code: %d", resp.StatusCode)
	}

	var tr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    []struct {
			Name    string  `json:"name"`
			Current float64 `json:"current"`
			Min     float64 `json:"min"`
			Max     float64 `json:"max"`
			State   string  `json:"state"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.Code != 0 {
		return nil, fmt.Errorf("tempratureInfo failed: code=%d message=%s", tr.Code, tr.Message)
	}

	metrics := make([]core.Metric, 0, len(tr.Data)*4)
	for _, sensor := range tr.Data {
		status := 0.0
		switch strings.TrimSpace(sensor.State) {
		case "Normal":
			status = 1
		case "Abnormal":
			status = 0
		default:
			status = 0
		}

		labels := map[string]string{
			"device_name": dev.Name,
			"vendor":      dev.Vendor,
			"role":        dev.Type,
			"sensor_name": strings.TrimSpace(sensor.Name),
		}

		metrics = append(metrics,
			core.Metric{Name: "netsec_system_temperature_status", Value: status, Labels: labels},
			core.Metric{Name: "netsec_system_temperature_current_celsius", Value: sensor.Current, Labels: labels},
			core.Metric{Name: "netsec_system_temperature_min_celsius", Value: sensor.Min, Labels: labels},
			core.Metric{Name: "netsec_system_temperature_max_celsius", Value: sensor.Max, Labels: labels},
		)
	}

	return metrics, nil
}
