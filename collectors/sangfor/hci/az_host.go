package hci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

type azItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Type    string `json:"type"`
	Tag     string `json:"tag"`
	Version string `json:"version"`
}

type azDetail struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Status            string             `json:"status"`
	Type              string             `json:"type"`
	Tag               string             `json:"tag"`
	Version           string             `json:"version"`
	VirtualResources  []virtualResource  `json:"virtual_resources"`
	PhysicalResources []physicalResource `json:"physical_resources"`
}

type hostCPU struct {
	TotalMHz  float64 `json:"total_mhz"`
	UsedMHz   float64 `json:"used_mhz"`
	Ratio     float64 `json:"ratio"`
	CoreCount float64 `json:"core_count"`
}

type hostMem struct {
	TotalMB float64 `json:"total_mb"`
	UsedMB  float64 `json:"used_mb"`
	Ratio   float64 `json:"ratio"`
}

type hostGPU struct {
	Total         float64 `json:"total"`
	Used          float64 `json:"used"`
	Ratio         float64 `json:"ratio"`
	MemoryTotalMB float64 `json:"memory_total_mb"`
	MemoryUsedMB  float64 `json:"memory_used_mb"`
	MemoryRatio   float64 `json:"memory_ratio"`
}

type hostItem struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	IP         string  `json:"ip"`
	AZID       string  `json:"az_id"`
	Status     string  `json:"status"`
	AlarmCount float64 `json:"alarm_count"`
	CPU        hostCPU `json:"cpu"`
	Memory     hostMem `json:"memory"`
	GPU        hostGPU `json:"gpu"`
}

func CollectAZAndHostMetrics(c *client.HCIClient, sess client.HCISession, dev core.Device) ([]core.Metric, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
	defer cancel()

	azs, err := listAZs(ctx, c, sess)
	if err != nil {
		return nil, err
	}

	base := map[string]string{
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"role":        dev.Type,
	}

	var out []core.Metric

	for _, az := range azs {
		azLabels := cloneLabels(base)
		azLabels["az_id"] = az.ID
		azLabels["az_name"] = az.Name

		out = append(out, core.Metric{Name: "netsec_hci_az_info", Value: 1, Labels: azLabels})

		detail, err := getAZDetail(ctx, c, sess, az.ID)
		if err != nil {
			return nil, err
		}

		for _, vr := range detail.VirtualResources {
			labels := cloneLabels(azLabels)
			labels["resource_name"] = vr.Name
			unit := strings.TrimSpace(vr.Unit)
			if factor, ok := bytesFactor(unit); ok {
				out = append(out,
					core.Metric{Name: "netsec_hci_az_virtual_resource_limit_bytes", Value: vr.Limit * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_virtual_resource_total_bytes", Value: vr.Total * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_virtual_resource_allocated_bytes", Value: vr.Allocated * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_virtual_resource_occupied_bytes", Value: vr.Occupied * factor, Labels: labels},
				)
				continue
			}
			if factor, ok := hzFactor(unit); ok {
				out = append(out,
					core.Metric{Name: "netsec_hci_az_virtual_resource_limit_hz", Value: vr.Limit * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_virtual_resource_total_hz", Value: vr.Total * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_virtual_resource_allocated_hz", Value: vr.Allocated * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_virtual_resource_occupied_hz", Value: vr.Occupied * factor, Labels: labels},
				)
			}
		}

		for _, pr := range detail.PhysicalResources {
			labels := cloneLabels(azLabels)
			labels["resource_name"] = pr.Name
			unit := strings.TrimSpace(pr.Unit)
			if factor, ok := bytesFactor(unit); ok {
				out = append(out,
					core.Metric{Name: "netsec_hci_az_physical_resource_total_bytes", Value: pr.Total * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_physical_resource_used_bytes", Value: pr.Used * factor, Labels: labels},
				)
				continue
			}
			if factor, ok := hzFactor(unit); ok {
				out = append(out,
					core.Metric{Name: "netsec_hci_az_physical_resource_total_hz", Value: pr.Total * factor, Labels: labels},
					core.Metric{Name: "netsec_hci_az_physical_resource_used_hz", Value: pr.Used * factor, Labels: labels},
				)
			}
		}

		hosts, err := listHosts(ctx, c, sess, az.ID)
		if err != nil {
			return nil, err
		}
		for _, h := range hosts {
			hostLabels := cloneLabels(azLabels)
			hostLabels["host_id"] = h.ID
			hostLabels["host_name"] = h.Name
			hostLabels["host_ip"] = h.IP

			out = append(out,
				core.Metric{Name: "netsec_hci_host_alarm_count", Value: h.AlarmCount, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_cpu_usage_ratio", Value: h.CPU.Ratio, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_cpu_total_mhz", Value: h.CPU.TotalMHz, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_cpu_used_mhz", Value: h.CPU.UsedMHz, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_cpu_core_count", Value: h.CPU.CoreCount, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_memory_usage_ratio", Value: h.Memory.Ratio, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_memory_total_bytes", Value: h.Memory.TotalMB * 1024 * 1024, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_memory_used_bytes", Value: h.Memory.UsedMB * 1024 * 1024, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_gpu_usage_ratio", Value: h.GPU.Ratio, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_gpu_total_count", Value: h.GPU.Total, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_gpu_used_count", Value: h.GPU.Used, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_gpu_memory_usage_ratio", Value: h.GPU.MemoryRatio, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_gpu_memory_total_bytes", Value: h.GPU.MemoryTotalMB * 1024 * 1024, Labels: hostLabels},
				core.Metric{Name: "netsec_hci_host_gpu_memory_used_bytes", Value: h.GPU.MemoryUsedMB * 1024 * 1024, Labels: hostLabels},
			)
		}
	}

	return out, nil
}

func listAZs(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]azItem, error) {
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/azs?type=hci", nil, &raw); err != nil {
		return nil, err
	}

	var azs []azItem
	if err := json.Unmarshal(raw, &azs); err == nil {
		return azs, nil
	}

	var wrapped struct {
		Message string   `json:"message"`
		Code    int      `json:"code"`
		Data    []azItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("az list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}

func getAZDetail(ctx context.Context, c *client.HCIClient, sess client.HCISession, azID string) (azDetail, error) {
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/azs/"+azID, nil, &raw); err != nil {
		return azDetail{}, err
	}

	var d azDetail
	if err := json.Unmarshal(raw, &d); err == nil && strings.TrimSpace(d.ID) != "" {
		return d, nil
	}

	var wrapped struct {
		Message string   `json:"message"`
		Code    int      `json:"code"`
		Data    azDetail `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return azDetail{}, err
	}
	if wrapped.Code != 0 {
		return azDetail{}, fmt.Errorf("az detail failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}

func listHosts(ctx context.Context, c *client.HCIClient, sess client.HCISession, azID string) ([]hostItem, error) {
	path := "/janus/20180725/hosts"
	if strings.TrimSpace(azID) != "" {
		path = path + "?az_id=" + azID
	}

	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", path, nil, &raw); err != nil {
		return nil, err
	}

	var hosts []hostItem
	if err := json.Unmarshal(raw, &hosts); err == nil {
		return hosts, nil
	}

	var wrapped struct {
		Message string     `json:"message"`
		Code    int        `json:"code"`
		Data    []hostItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("host list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}
