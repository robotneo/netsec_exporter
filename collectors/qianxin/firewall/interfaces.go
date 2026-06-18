package firewall

import (
	"context"
	"strconv"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectInterfaceMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	metrics := []core.Metric{}
	var lastErr error
	labelsByIfName := map[string]map[string]string{}

	req := []client.RESTRequest{
		{
			Head: client.RESTHead{
				Module:    "inter_face",
				PageIndex: 1,
				PageSize:  50,
				Function:  "show_all_interface_web",
			},
			Body: client.RESTBody{
				Data: map[string]any{
					"info": map[string]any{
						"interface": map[string]any{},
						"filter": map[string]any{
							"inf_type": "physical",
							"inf_desc": "",
							"inf_name": "",
							"inf_zone": "",
						},
					},
				},
			},
		},
	}

	var resp qianxinInterfaceResponse
	if postErr := c.PostREST(context.Background(), dev, sess, req, &resp); postErr == nil {
		if okErr := client.EnsureRESTOK("show_all_interface_web", resp.Head); okErr == nil {
			for _, inf := range resp.Data.Interface {
				ifName := strings.TrimSpace(inf.Name)
				if ifName == "" {
					continue
				}

				labels := map[string]string{
					"if_name":     ifName,
					"description": strings.TrimSpace(inf.Alias),
					"zone":        strings.TrimSpace(inf.Zone),
					"mac":         strings.TrimSpace(inf.HardwareAddr),
					"ip_addr":     collectInterfaceIPs(inf),
				}
				labelsByIfName[ifName] = labels

				metrics = append(metrics,
					core.Metric{Name: "netsec_interface_physical_state", Value: mapInterfaceStatus(inf.Status), Labels: labels},
					core.Metric{Name: "netsec_interface_link_state", Value: mapInterfaceLink(inf.Link), Labels: labels},
					core.Metric{Name: "netsec_interface_mtu_bytes", Value: parseStringFloat(inf.MTU), Labels: labels},
					core.Metric{Name: "netsec_interface_speed_mbps", Value: parseInterfaceSpeedMbps(inf.CurrentSpeed), Labels: labels},
					core.Metric{Name: "netsec_interface_role", Value: mapInterfaceRole(inf.IsWAN), Labels: labels},
					core.Metric{Name: "netsec_interface_layer_mode", Value: mapInterfaceMode(inf.Mode), Labels: labels},
				)
			}
		} else {
			lastErr = okErr
		}
	} else {
		lastErr = postErr
	}

	reqTraffic := []client.RESTRequest{
		{
			Head: client.RESTHead{
				Function:  "get_interface_info",
				Module:    "dashboard",
				PageIndex: 1,
				PageSize:  3000,
			},
			Body: client.RESTBody{
				Data: map[string]any{
					"group_by": "interface",
					"order_by": "bytes",
					"time":     "",
				},
			},
		},
	}

	var tr qianxinInterfaceFlowResponse
	if postErr := c.PostREST(context.Background(), dev, sess, reqTraffic, &tr); postErr == nil {
		if okErr := client.EnsureRESTOK("get_interface_info", tr.Head); okErr == nil {
			for _, item := range tr.Data {
				ifName := strings.TrimSpace(item.Name)
				if ifName == "" {
					continue
				}

				labels := labelsByIfName[ifName]
				if labels == nil {
					labels = map[string]string{
						"if_name":     ifName,
						"description": strings.TrimSpace(item.Alias),
						"zone":        "",
						"mac":         "",
						"ip_addr":     "",
					}
				}

				inBps := parseFlowToBps(item.InFlow)
				outBps := parseFlowToBps(item.OutFlow)
				metrics = append(metrics,
					core.Metric{Name: "netsec_interface_traffic_in_bps", Value: inBps, Labels: labels},
					core.Metric{Name: "netsec_interface_traffic_out_bps", Value: outBps, Labels: labels},
				)
			}
		} else {
			lastErr = okErr
		}
	} else {
		lastErr = postErr
	}

	if len(metrics) > 0 {
		return metrics, nil
	}
	return nil, lastErr
}

type qianxinInterfaceResponse struct {
	Head client.RESTResponseHead `json:"head"`
	Data struct {
		Interface []qianxinInterfaceEntry `json:"interface"`
	} `json:"data"`
}

type qianxinInterfaceEntry struct {
	Name         string `json:"name"`
	Alias        string `json:"alias"`
	MTU          string `json:"mtu"`
	CurrentSpeed string `json:"current_speed"`
	Status       string `json:"status"`
	Mode         string `json:"mode"`
	Link         string `json:"link"`
	HardwareAddr string `json:"hardware_addr"`
	Zone         string `json:"zone"`
	IsWAN        string `json:"is_wan"`
	IPList       []struct {
		IPAddr string `json:"ipaddr"`
		Mask   string `json:"mask"`
	} `json:"iplist"`
	IPAddr string `json:"ipaddr"`
}

type qianxinInterfaceFlowResponse struct {
	Head client.RESTResponseHead     `json:"head"`
	Data []qianxinInterfaceFlowEntry `json:"data"`
}

type qianxinInterfaceFlowEntry struct {
	Name    string `json:"name"`
	Alias   string `json:"alias"`
	Speed   string `json:"speed"`
	Status  string `json:"status"`
	InFlow  string `json:"in_flow"`
	OutFlow string `json:"out_flow"`
}

func collectInterfaceIPs(inf qianxinInterfaceEntry) string {
	if ip := strings.TrimSpace(inf.IPAddr); ip != "" {
		return ip
	}

	ips := make([]string, 0, len(inf.IPList))
	for _, item := range inf.IPList {
		ip := strings.TrimSpace(item.IPAddr)
		mask := strings.TrimSpace(item.Mask)
		if ip == "" {
			continue
		}
		if mask != "" {
			ips = append(ips, ip+"/"+mask)
			continue
		}
		ips = append(ips, ip)
	}
	return strings.Join(ips, ",")
}

func mapInterfaceStatus(status string) float64 {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "enable", "enabled", "up", "true":
		return 1
	default:
		return 0
	}
}

func mapInterfaceLink(link string) float64 {
	switch strings.ToLower(strings.TrimSpace(link)) {
	case "up", "true":
		return 1
	default:
		return 0
	}
}

func mapInterfaceRole(role string) float64 {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "wan":
		return 1
	default:
		return 0
	}
}

func mapInterfaceMode(mode string) float64 {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "layer3":
		return 1
	case "layer2":
		return 0
	default:
		return 0
	}
}

func parseStringFloat(raw string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return v
}

func parseInterfaceSpeedMbps(raw string) float64 {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0
	}

	left := s
	unit := ""
	if idx := strings.Index(s, "("); idx >= 0 {
		left = strings.TrimSpace(s[:idx])
		if end := strings.Index(s[idx:], ")"); end >= 0 {
			unit = strings.TrimSpace(s[idx+1 : idx+end])
		}
	}

	val, err := strconv.ParseFloat(left, 64)
	if err != nil {
		return 0
	}

	switch strings.ToLower(strings.TrimSpace(unit)) {
	case "gb/s", "gbps", "gbit/s":
		return val * 1000
	case "mb/s", "mbps", "mbit/s":
		return val
	case "kb/s", "kbps", "kbit/s":
		return val / 1000
	case "bps", "bit/s":
		return val / 1000 / 1000
	case "":
		return val
	default:
		return val
	}
}

func parseFlowToBps(raw string) float64 {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0
	}

	left := s
	unit := ""
	if idx := strings.Index(s, "("); idx >= 0 {
		left = strings.TrimSpace(s[:idx])
		if end := strings.Index(s[idx:], ")"); end >= 0 {
			unit = strings.TrimSpace(s[idx+1 : idx+end])
		}
	}

	val, err := strconv.ParseFloat(left, 64)
	if err != nil {
		return 0
	}

	u := strings.ToLower(strings.TrimSpace(unit))
	switch u {
	case "gbps", "gbit/s", "gb/s":
		return val * 1e9
	case "mbps", "mbit/s", "mb/s":
		return val * 1e6
	case "kbps", "kbit/s", "kb/s":
		return val * 1e3
	case "bps", "bit/s", "":
		return val
	default:
		if strings.Contains(u, "gb") {
			return val * 1e9
		}
		if strings.Contains(u, "mb") {
			return val * 1e6
		}
		if strings.Contains(u, "kb") {
			return val * 1e3
		}
		return val
	}
}
