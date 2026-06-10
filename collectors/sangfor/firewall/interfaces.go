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
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"role":        dev.Type,
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

func CollectInterfaces(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	type ipAddr struct {
		Start string `json:"start"`
		Bits  int    `json:"bits"`
	}
	type staticIPEntry struct {
		IPAddress ipAddr `json:"ipaddress"`
	}
	type ipv4Info struct {
		IPv4Mode string          `json:"ipv4Mode"`
		StaticIP []staticIPEntry `json:"staticIp"`
	}
	type speedDuplex struct {
		Speed float64 `json:"speed"`
	}
	type ethInterface struct {
		PhysicalStatus bool        `json:"physicalStatus"`
		LinkStatus     bool        `json:"linkStatus"`
		Name           string      `json:"name"`
		Description    string      `json:"description"`
		Zone           string      `json:"zone"`
		MAC            string      `json:"mac"`
		MTU            float64     `json:"mtu"`
		Ping           *bool       `json:"ping"`
		WanEnable      string      `json:"wanEnable"`
		EthToolType    string      `json:"ethToolType"`
		IfType         string      `json:"ifType"`
		IfMode         string      `json:"ifMode"`
		SpeedDuplex    speedDuplex `json:"speedDuplex"`
		SendSpeed      string      `json:"sendSpeed"`
		RecvSpeed      string      `json:"recvSpeed"`
		SendPackets    float64     `json:"sendPackets"`
		RecvPackets    float64     `json:"recvPackets"`
		FlowUnit       string      `json:"flowUnit"`
		IPv4           ipv4Info    `json:"ipv4"`
	}

	type response struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Data struct {
				Eth []ethInterface `json:"eth"`
			} `json:"data"`
			Eth []ethInterface `json:"eth"`
		} `json:"data"`
	}

	endpoints := []string{
		fmt.Sprintf("https://%s/api/v1/namespaces/%s/interfaces", dev.Host, sess.Namespace),
		fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/interfaces", dev.Host),
		fmt.Sprintf("https://%s/api/v1/namespaces/%s/interfacetraffics", dev.Host, sess.Namespace),
		fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/interfacetraffics", dev.Host),
	}

	var lastErr error
	for _, apiURL := range endpoints {
		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("AuthorizationToken", sess.Token)

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		metrics, hasEth, err := func() ([]core.Metric, bool, error) {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				return nil, false, nil
			}
			if resp.StatusCode != http.StatusOK {
				return nil, false, fmt.Errorf("interfaces api status code: %d", resp.StatusCode)
			}

			var r response
			if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
				return nil, false, err
			}
			if r.Code != 0 {
				return nil, false, fmt.Errorf("interfaces failed: code=%d message=%s", r.Code, r.Message)
			}

			eths := r.Data.Data.Eth
			if len(eths) == 0 {
				eths = r.Data.Eth
			}
			if len(eths) == 0 {
				return nil, false, nil
			}

			var metrics []core.Metric
			for _, eth := range eths {
				baseLabels := map[string]string{
					"if_name":     eth.Name,
					"description": eth.Description,
					"zone":        eth.Zone,
					"mac":         eth.MAC,
					"ip_addr":     "",
				}

				if eth.PhysicalStatus && eth.LinkStatus && strings.EqualFold(strings.TrimSpace(eth.IPv4.IPv4Mode), "STATIC") {
					var ips []string
					for _, ip := range eth.IPv4.StaticIP {
						start := strings.TrimSpace(ip.IPAddress.Start)
						if start == "" {
							continue
						}
						if ip.IPAddress.Bits > 0 {
							ips = append(ips, fmt.Sprintf("%s/%d", start, ip.IPAddress.Bits))
						} else {
							ips = append(ips, start)
						}
					}
					if len(ips) > 0 {
						baseLabels["ip_addr"] = strings.Join(ips, ",")
					}
				}

				ping := 0.0
				if eth.Ping != nil && *eth.Ping {
					ping = 1
				}

				wanEnable := 0.0
				switch strings.ToUpper(strings.TrimSpace(eth.WanEnable)) {
				case "ENABLE":
					wanEnable = 1
				case "DISABLE":
					wanEnable = 0
				}

				ethToolType := 0.0
				ett := strings.ToUpper(strings.TrimSpace(eth.EthToolType))
				switch {
				case strings.Contains(ett, "FIBER"):
					ethToolType = 1
				case strings.HasPrefix(ett, "TP"):
					ethToolType = 0
				}

				ifTypePhysical := 0.0
				if strings.ToUpper(strings.TrimSpace(eth.IfType)) == "PHYSICALIF" {
					ifTypePhysical = 1
				}

				ifMode := 0.0
				switch strings.ToUpper(strings.TrimSpace(eth.IfMode)) {
				case "ROUTE":
					ifMode = 1
				case "BRIDGE":
					ifMode = 0
				}

				sendBps := 0.0
				recvBps := 0.0
				if strings.TrimSpace(eth.SendSpeed) != "" {
					val, err := parseThroughputToBitsPerSecond(eth.SendSpeed, "bps")
					if err == nil {
						sendBps = val
					}
				}
				if strings.TrimSpace(eth.RecvSpeed) != "" {
					val, err := parseThroughputToBitsPerSecond(eth.RecvSpeed, "bps")
					if err == nil {
						recvBps = val
					}
				}

				metrics = append(metrics,
					core.Metric{Name: "netsec_interface_physical_state", Value: boolTo01(eth.PhysicalStatus), Labels: baseLabels},
					core.Metric{Name: "netsec_interface_link_state", Value: boolTo01(eth.LinkStatus), Labels: baseLabels},
					core.Metric{Name: "netsec_interface_mtu_bytes", Value: eth.MTU, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_ping_up", Value: ping, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_role", Value: wanEnable, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_media_type", Value: ethToolType, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_category", Value: ifTypePhysical, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_layer_mode", Value: ifMode, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_speed_mbps", Value: eth.SpeedDuplex.Speed, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_traffic_out_bps", Value: sendBps, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_traffic_in_bps", Value: recvBps, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_traffic_out_packets_total", Value: eth.SendPackets, Labels: baseLabels},
					core.Metric{Name: "netsec_interface_traffic_in_packets_total", Value: eth.RecvPackets, Labels: baseLabels},
				)
			}

			return metrics, true, nil
		}()
		if err != nil {
			return nil, err
		}
		if hasEth {
			return metrics, nil
		}
		lastErr = fmt.Errorf("interfaces empty eth")
		continue
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("interfaces fetch failed")
	}
	return nil, lastErr
}

func boolTo01(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
