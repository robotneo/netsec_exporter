package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"netsec_exporter/collectors/dbapp/client"
	"netsec_exporter/core"
)

type interfacesConfigResp struct {
	Vals []struct {
		Enabled     bool     `json:"enabled"`
		Name        string   `json:"name"`
		Mode        string   `json:"mode"`
		IPAddresses []string `json:"ip_addresses"`
		Service     struct {
			Ping bool `json:"ping"`
		} `json:"service"`
		SMAC      []string  `json:"smac"`
		MTUs      []float64 `json:"mtus"`
		OtherName string    `json:"otherName"`
		Type      float64   `json:"type"`
		VLType    string    `json:"vltype"`
	} `json:"vals"`
}

type interfacesStatResp struct {
	Vals []struct {
		Name           string    `json:"name"`
		IsAdminStateUp bool      `json:"is_admin_state_up"`
		IsLinkStateUp  bool      `json:"is_link_state_up"`
		LinkSpeed      float64   `json:"link_speed"`
		LinkMTU        float64   `json:"link_mtu"`
		MTUs           []float64 `json:"mtus"`
		L2Address      string    `json:"l2_address"`
		RXPackets      float64   `json:"rx_packets"`
		RXBytesSpeed   float64   `json:"rx_bytes_speed"`
		TXPackets      float64   `json:"tx_packets"`
		TXBytesSpeed   float64   `json:"tx_bytes_speed"`
	} `json:"vals"`
}

func CollectInterfaces(c *client.Client, dev core.Device) ([]core.Metric, error) {
	cfg, cfgByName, err := collectInterfacesConfigMetrics(c, dev)
	if err != nil {
		return nil, err
	}

	stat, err := collectInterfacesStatMetrics(c, dev, cfgByName)
	if err != nil {
		return cfg, nil
	}

	metrics := append([]core.Metric{}, cfg...)
	metrics = append(metrics, stat...)
	return metrics, nil
}

func collectInterfacesConfigMetrics(c *client.Client, dev core.Device) ([]core.Metric, map[string]map[string]string, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/intf", dev.Host)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("AuthorizationToken", dev.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("intf api status code: %d", resp.StatusCode)
	}

	var r interfacesConfigResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, nil, err
	}

	byName := make(map[string]map[string]string, len(r.Vals))
	metrics := make([]core.Metric, 0, len(r.Vals)*3)
	for _, itf := range r.Vals {
		baseLabels := map[string]string{
			"if_name":     itf.Name,
			"description": strings.TrimSpace(itf.OtherName),
			"zone":        "",
			"mac":         "",
			"ip_addr":     "",
		}

		if len(itf.SMAC) > 0 {
			baseLabels["mac"] = strings.Join(itf.SMAC, ",")
		}
		if len(itf.IPAddresses) > 0 {
			baseLabels["ip_addr"] = strings.Join(itf.IPAddresses, ",")
		}

		ping := 0.0
		if itf.Service.Ping {
			ping = 1
		}

		ifMode := 0.0
		switch strings.ToUpper(strings.TrimSpace(itf.Mode)) {
		case "ROUTE":
			ifMode = 1
		case "BRIDGE":
			ifMode = 0
		}

		ifTypePhysical := 0.0
		nameUpper := strings.ToUpper(strings.TrimSpace(itf.Name))
		if strings.HasPrefix(nameUpper, "GE") || itf.Type == 3 || strings.ToUpper(strings.TrimSpace(itf.VLType)) == "VPP" {
			ifTypePhysical = 1
		}

		byName[itf.Name] = baseLabels

		metrics = append(metrics,
			core.Metric{Name: "netsec_interface_ping_up", Value: ping, Labels: baseLabels},
			core.Metric{Name: "netsec_interface_layer_mode", Value: ifMode, Labels: baseLabels},
			core.Metric{Name: "netsec_interface_category", Value: ifTypePhysical, Labels: baseLabels},
		)
	}

	return metrics, byName, nil
}

func collectInterfacesStatMetrics(c *client.Client, dev core.Device, cfgByName map[string]map[string]string) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/intf/stat", dev.Host)

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
		return nil, fmt.Errorf("intf/stat api status code: %d", resp.StatusCode)
	}

	var r interfacesStatResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}

	metrics := make([]core.Metric, 0, len(r.Vals)*6)
	for _, st := range r.Vals {
		labels := map[string]string{
			"if_name":     st.Name,
			"description": "",
			"zone":        "",
			"mac":         "",
			"ip_addr":     "",
		}

		if cfg, ok := cfgByName[st.Name]; ok {
			for k, v := range cfg {
				labels[k] = v
			}
		}

		if strings.TrimSpace(labels["mac"]) == "" && strings.TrimSpace(st.L2Address) != "" {
			labels["mac"] = st.L2Address
		}

		mtu := st.LinkMTU
		if mtu <= 0 {
			for _, v := range st.MTUs {
				if v > 0 {
					mtu = v
					break
				}
			}
		}

		metrics = append(metrics,
			core.Metric{Name: "netsec_interface_physical_state", Value: boolTo01(st.IsAdminStateUp), Labels: labels},
			core.Metric{Name: "netsec_interface_link_state", Value: boolTo01(st.IsLinkStateUp), Labels: labels},
			core.Metric{Name: "netsec_interface_mtu_bytes", Value: mtu, Labels: labels},
			core.Metric{Name: "netsec_interface_speed_mbps", Value: st.LinkSpeed, Labels: labels},
			core.Metric{Name: "netsec_interface_traffic_in_bps", Value: st.RXBytesSpeed * 8, Labels: labels},
			core.Metric{Name: "netsec_interface_traffic_out_bps", Value: st.TXBytesSpeed * 8, Labels: labels},
			core.Metric{Name: "netsec_interface_traffic_in_packets_total", Value: st.RXPackets, Labels: labels},
			core.Metric{Name: "netsec_interface_traffic_out_packets_total", Value: st.TXPackets, Labels: labels},
		)
	}

	return metrics, nil
}

func boolTo01(v bool) float64 {
	if v {
		return 1
	}
	return 0
}
