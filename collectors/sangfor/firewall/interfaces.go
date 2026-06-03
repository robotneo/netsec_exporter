package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectInterfaceTrafficBits(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/interfacetraffics", dev.Host, sess.Namespace)

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
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/interfacetraffics", dev.Host)
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
		return nil, fmt.Errorf("interfacetraffics api status code: %d", resp.StatusCode)
	}

	var tr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Data struct {
				Speeds []struct {
					SendSpeed float64 `json:"sendSpeed"`
					RecvSpeed float64 `json:"recvSpeed"`
					Time      string  `json:"time"`
				} `json:"speeds"`
				Unit          string `json:"unit"`
				RealTimeSpeed struct {
					SendSpeed string `json:"sendSpeed"`
					RecvSpeed string `json:"recvSpeed"`
				} `json:"realTimeSpeed"`
			} `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.Code != 0 {
		return nil, fmt.Errorf("interfacetraffics failed: code=%d message=%s", tr.Code, tr.Message)
	}

	labels := map[string]string{
		"device": dev.Name,
		"vendor": dev.Vendor,
		"type":   dev.Type,
	}

	if strings.TrimSpace(tr.Data.Data.RealTimeSpeed.SendSpeed) != "" || strings.TrimSpace(tr.Data.Data.RealTimeSpeed.RecvSpeed) != "" {
		sendBps, err := parseThroughputToBitsPerSecond(tr.Data.Data.RealTimeSpeed.SendSpeed, tr.Data.Data.Unit)
		if err != nil {
			return nil, err
		}
		recvBps, err := parseThroughputToBitsPerSecond(tr.Data.Data.RealTimeSpeed.RecvSpeed, tr.Data.Data.Unit)
		if err != nil {
			return nil, err
		}

		return []core.Metric{
			{
				Name:   "netsec_interface_send_bits",
				Value:  sendBps,
				Labels: labels,
			},
			{
				Name:   "netsec_interface_recv_bits",
				Value:  recvBps,
				Labels: labels,
			},
		}, nil
	}

	if len(tr.Data.Data.Speeds) == 0 {
		return nil, fmt.Errorf("interfacetraffics empty speeds")
	}

	layout := "2006-01-02 15:04:05"
	latestIdx := 0
	latestTime, err := time.Parse(layout, tr.Data.Data.Speeds[0].Time)
	if err != nil {
		return nil, fmt.Errorf("interfacetraffics parse time failed: %w", err)
	}
	for i := 1; i < len(tr.Data.Data.Speeds); i++ {
		t, err := time.Parse(layout, tr.Data.Data.Speeds[i].Time)
		if err != nil {
			continue
		}
		if t.After(latestTime) {
			latestTime = t
			latestIdx = i
		}
	}

	factor, err := trafficUnitToBitsFactor(tr.Data.Data.Unit)
	if err != nil {
		return nil, err
	}

	return []core.Metric{
		{
			Name:   "netsec_interface_send_bits",
			Value:  tr.Data.Data.Speeds[latestIdx].SendSpeed * factor,
			Labels: labels,
		},
		{
			Name:   "netsec_interface_recv_bits",
			Value:  tr.Data.Data.Speeds[latestIdx].RecvSpeed * factor,
			Labels: labels,
		},
	}, nil
}

func parseThroughputToBitsPerSecond(s string, fallbackUnit string) (float64, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return 0, fmt.Errorf("interfacetraffics empty realTimeSpeed")
	}

	compact := strings.ReplaceAll(raw, " ", "")
	startUnit := -1
	for i := 0; i < len(compact); i++ {
		ch := compact[i]
		if (ch >= '0' && ch <= '9') || ch == '.' {
			continue
		}
		startUnit = i
		break
	}

	valueStr := compact
	unitStr := ""
	if startUnit >= 0 {
		valueStr = compact[:startUnit]
		unitStr = compact[startUnit:]
	}

	if unitStr == "" {
		unitStr = fallbackUnit
	}

	val, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return 0, fmt.Errorf("interfacetraffics parse realTimeSpeed value failed: %s", s)
	}

	factor, err := trafficUnitToBitsFactor(unitStr)
	if err != nil {
		return 0, err
	}
	return val * factor, nil
}

func trafficUnitToBitsFactor(unit string) (float64, error) {
	u := strings.TrimSpace(unit)
	if u == "" {
		return 1, nil
	}

	normalized := strings.ToLower(u)
	normalized = strings.ReplaceAll(normalized, " ", "")
	normalized = strings.ReplaceAll(normalized, "/s", "ps")
	normalized = strings.ReplaceAll(normalized, "/sec", "ps")

	switch {
	case strings.Contains(normalized, "tbps"):
		return 1e12, nil
	case strings.Contains(normalized, "gbps"):
		return 1e9, nil
	case strings.Contains(normalized, "mbps"):
		return 1e6, nil
	case strings.Contains(normalized, "kbps"):
		return 1e3, nil
	case strings.Contains(normalized, "bps"):
		return 1, nil
	}

	if strings.Contains(u, "B") || strings.Contains(normalized, "byte") {
		switch {
		case strings.Contains(normalized, "tb"):
			return 8e12, nil
		case strings.Contains(normalized, "gb"):
			return 8e9, nil
		case strings.Contains(normalized, "mb"):
			return 8e6, nil
		case strings.Contains(normalized, "kb"):
			return 8e3, nil
		case strings.Contains(normalized, "b"):
			return 8, nil
		}
	}

	return 0, fmt.Errorf("interfacetraffics unsupported unit: %s", unit)
}
