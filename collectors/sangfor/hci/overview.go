package hci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

type overviewResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Data    struct {
		VirtualResources  []virtualResource  `json:"virtual_resources"`
		PhysicalResources []physicalResource `json:"physical_resources"`
		Host              countBlock         `json:"host"`
		Server            serverCountBlock   `json:"server"`
		NFV               nfvCountBlock      `json:"nfv"`
		AZ                countBlock         `json:"az"`
	} `json:"data"`
}

type countBlock struct {
	Total        float64 `json:"total"`
	OnlineCount  float64 `json:"online_count"`
	OfflineCount float64 `json:"offline_count"`
	AlarmCount   float64 `json:"alarm_count"`
}

type serverCountBlock struct {
	Total        float64 `json:"total"`
	RunningCount float64 `json:"running_count"`
	OfflineCount float64 `json:"offline_count"`
	AlarmCount   float64 `json:"alarm_count"`
	ErrorCount   float64 `json:"error_count"`
}

type nfvCountBlock struct {
	Total        float64 `json:"total"`
	RunningCount float64 `json:"running_count"`
	OfflineCount float64 `json:"offline_count"`
	ErrorCount   float64 `json:"error_count"`
}

type virtualResource struct {
	Name      string  `json:"name"`
	Limit     float64 `json:"limit"`
	Total     float64 `json:"total"`
	Allocated float64 `json:"allocated"`
	Occupied  float64 `json:"occupied"`
	Unit      string  `json:"unit"`
}

type physicalResource struct {
	Name  string  `json:"name"`
	Total float64 `json:"total"`
	Used  float64 `json:"used"`
	Unit  string  `json:"unit"`
}

func CollectOverviewMetrics(c *client.HCIClient, sess client.HCISession, dev core.Device) ([]core.Metric, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
	defer cancel()

	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/overview", nil, &raw); err != nil {
		return nil, err
	}

	var r overviewResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.Code != 0 {
		return nil, fmt.Errorf("overview failed: code=%d message=%s", r.Code, r.Message)
	}

	base := map[string]string{
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"type":        dev.Type,
	}

	var out []core.Metric
	out = append(out,
		core.Metric{Name: "netsec_hci_overview_hosts_total", Value: r.Data.Host.Total, Labels: base},
		core.Metric{Name: "netsec_hci_overview_hosts_online", Value: r.Data.Host.OnlineCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_hosts_offline", Value: r.Data.Host.OfflineCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_hosts_alarm", Value: r.Data.Host.AlarmCount, Labels: base},

		core.Metric{Name: "netsec_hci_overview_servers_total", Value: r.Data.Server.Total, Labels: base},
		core.Metric{Name: "netsec_hci_overview_servers_running", Value: r.Data.Server.RunningCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_servers_offline", Value: r.Data.Server.OfflineCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_servers_alarm", Value: r.Data.Server.AlarmCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_servers_error", Value: r.Data.Server.ErrorCount, Labels: base},

		core.Metric{Name: "netsec_hci_overview_az_total", Value: r.Data.AZ.Total, Labels: base},
		core.Metric{Name: "netsec_hci_overview_az_online", Value: r.Data.AZ.OnlineCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_az_offline", Value: r.Data.AZ.OfflineCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_az_alarm", Value: r.Data.AZ.AlarmCount, Labels: base},

		core.Metric{Name: "netsec_hci_overview_nfv_total", Value: r.Data.NFV.Total, Labels: base},
		core.Metric{Name: "netsec_hci_overview_nfv_running", Value: r.Data.NFV.RunningCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_nfv_offline", Value: r.Data.NFV.OfflineCount, Labels: base},
		core.Metric{Name: "netsec_hci_overview_nfv_error", Value: r.Data.NFV.ErrorCount, Labels: base},
	)

	for _, vr := range r.Data.VirtualResources {
		labels := cloneLabels(base)
		labels["resource_name"] = vr.Name
		unit := strings.TrimSpace(vr.Unit)
		if factor, ok := bytesFactor(unit); ok {
			out = append(out,
				core.Metric{Name: "netsec_hci_overview_virtual_resource_limit_bytes", Value: vr.Limit * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_virtual_resource_total_bytes", Value: vr.Total * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_virtual_resource_allocated_bytes", Value: vr.Allocated * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_virtual_resource_occupied_bytes", Value: vr.Occupied * factor, Labels: labels},
			)
			continue
		}
		if factor, ok := hzFactor(unit); ok {
			out = append(out,
				core.Metric{Name: "netsec_hci_overview_virtual_resource_limit_hz", Value: vr.Limit * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_virtual_resource_total_hz", Value: vr.Total * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_virtual_resource_allocated_hz", Value: vr.Allocated * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_virtual_resource_occupied_hz", Value: vr.Occupied * factor, Labels: labels},
			)
		}
	}

	for _, pr := range r.Data.PhysicalResources {
		labels := cloneLabels(base)
		labels["resource_name"] = pr.Name
		unit := strings.TrimSpace(pr.Unit)
		if factor, ok := bytesFactor(unit); ok {
			out = append(out,
				core.Metric{Name: "netsec_hci_overview_physical_resource_total_bytes", Value: pr.Total * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_physical_resource_used_bytes", Value: pr.Used * factor, Labels: labels},
			)
			continue
		}
		if factor, ok := hzFactor(unit); ok {
			out = append(out,
				core.Metric{Name: "netsec_hci_overview_physical_resource_total_hz", Value: pr.Total * factor, Labels: labels},
				core.Metric{Name: "netsec_hci_overview_physical_resource_used_hz", Value: pr.Used * factor, Labels: labels},
			)
		}
	}

	return out, nil
}
