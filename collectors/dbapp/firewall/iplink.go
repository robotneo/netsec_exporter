package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"

	"netsec_exporter/collectors/dbapp/client"
	"netsec_exporter/core"
)

type ipLinkResp struct {
	Vals []struct {
		Name        string `json:"name"`
		Interface   string `json:"interface"`
		Destination string `json:"destination"`
		Status      bool   `json:"status"`
	} `json:"vals"`
}

func CollectIPLinkStatus(c *client.Client, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/iplink?page=1&size=10&key=", dev.Host)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AuthorizationToken", dev.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("api status code: %d", resp.StatusCode)
	}

	var r ipLinkResp
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
