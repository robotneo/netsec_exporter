package hci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

type vmCPUStatus struct {
	TotalMHz float64 `json:"total_mhz"`
	UsedMHz  float64 `json:"used_mhz"`
	Ratio    float64 `json:"ratio"`
}

type vmMemoryStatus struct {
	TotalMB float64 `json:"total_mb"`
	UsedMB  float64 `json:"used_mb"`
	Ratio   float64 `json:"ratio"`
}

type vmStorageStatus struct {
	TotalMB           float64 `json:"total_mb"`
	UsedMB            float64 `json:"used_mb"`
	Ratio             float64 `json:"ratio"`
	StorageFileSizeMB float64 `json:"storage_file_size_mb"`
}

type vmIOStatus struct {
	ReadSpeedByteps  float64 `json:"read_speed_byteps"`
	WriteSpeedByteps float64 `json:"write_speed_byteps"`
	ReadIOPS         float64 `json:"read_iops"`
	WriteIOPS        float64 `json:"write_iops"`
}

type vmNetworkStatus struct {
	ReadSpeedBitps  float64 `json:"read_speed_bitps"`
	WriteSpeedBitps float64 `json:"write_speed_bitps"`
}

type vmAlarm struct {
	Alarm float64 `json:"alarm"`
}

type vmItem struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Status        string          `json:"status"`
	Uptime        float64         `json:"uptime"`
	AZID          string          `json:"az_id"`
	AZName        string          `json:"az_name"`
	HostID        string          `json:"host_id"`
	HostName      string          `json:"host_name"`
	ProjectID     string          `json:"project_id"`
	ProjectName   string          `json:"project_name"`
	CPUStatus     vmCPUStatus     `json:"cpu_status"`
	MemoryStatus  vmMemoryStatus  `json:"memory_status"`
	StorageStatus vmStorageStatus `json:"storage_status"`
	IOStatus      vmIOStatus      `json:"io_status"`
	NetworkStatus vmNetworkStatus `json:"network_status"`
	Alarm         vmAlarm         `json:"alarm"`
}

func CollectVMMetrics(c *client.HCIClient, sess client.HCISession, dev core.Device) ([]core.Metric, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
	defer cancel()

	vms, err := listVMs(ctx, c, sess)
	if err != nil {
		return nil, err
	}

	base := map[string]string{
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"role":        dev.Type,
	}

	out := []core.Metric{
		{Name: "netsec_hci_vm_total", Value: float64(len(vms)), Labels: base},
	}

	for _, vm := range vms {
		labels := cloneLabels(base)
		labels["vm_id"] = vm.ID
		labels["vm_name"] = vm.Name
		if strings.TrimSpace(vm.AZID) != "" {
			labels["az_id"] = vm.AZID
		}
		if strings.TrimSpace(vm.AZName) != "" {
			labels["az_name"] = vm.AZName
		}
		if strings.TrimSpace(vm.HostID) != "" {
			labels["host_id"] = vm.HostID
		}
		if strings.TrimSpace(vm.HostName) != "" {
			labels["host_name"] = vm.HostName
		}
		if strings.TrimSpace(vm.ProjectID) != "" {
			labels["project_id"] = vm.ProjectID
		}
		if strings.TrimSpace(vm.ProjectName) != "" {
			labels["project_name"] = vm.ProjectName
		}

		out = append(out,
			core.Metric{Name: "netsec_hci_vm_uptime_seconds", Value: vm.Uptime, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_alarm", Value: vm.Alarm.Alarm, Labels: labels},

			core.Metric{Name: "netsec_hci_vm_cpu_usage_ratio", Value: vm.CPUStatus.Ratio, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_cpu_total_mhz", Value: vm.CPUStatus.TotalMHz, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_cpu_used_mhz", Value: vm.CPUStatus.UsedMHz, Labels: labels},

			core.Metric{Name: "netsec_hci_vm_memory_usage_ratio", Value: vm.MemoryStatus.Ratio, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_memory_total_bytes", Value: vm.MemoryStatus.TotalMB * 1024 * 1024, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_memory_used_bytes", Value: vm.MemoryStatus.UsedMB * 1024 * 1024, Labels: labels},

			core.Metric{Name: "netsec_hci_vm_storage_usage_ratio", Value: vm.StorageStatus.Ratio, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_storage_total_bytes", Value: vm.StorageStatus.TotalMB * 1024 * 1024, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_storage_used_bytes", Value: vm.StorageStatus.UsedMB * 1024 * 1024, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_storage_file_size_bytes", Value: vm.StorageStatus.StorageFileSizeMB * 1024 * 1024, Labels: labels},

			core.Metric{Name: "netsec_hci_vm_io_read_bytes_per_second", Value: vm.IOStatus.ReadSpeedByteps, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_io_write_bytes_per_second", Value: vm.IOStatus.WriteSpeedByteps, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_io_read_iops", Value: vm.IOStatus.ReadIOPS, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_io_write_iops", Value: vm.IOStatus.WriteIOPS, Labels: labels},

			core.Metric{Name: "netsec_hci_vm_network_read_bits_per_second", Value: vm.NetworkStatus.ReadSpeedBitps, Labels: labels},
			core.Metric{Name: "netsec_hci_vm_network_write_bits_per_second", Value: vm.NetworkStatus.WriteSpeedBitps, Labels: labels},
		)
	}

	return out, nil
}

func listVMs(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]vmItem, error) {
	path := "/janus/20180725/servers?page_num=0&page_size=1000"
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", path, nil, &raw); err != nil {
		return nil, err
	}

	var vms []vmItem
	if err := json.Unmarshal(raw, &vms); err == nil {
		return vms, nil
	}

	var wrappedList struct {
		Message string   `json:"message"`
		Code    int      `json:"code"`
		Data    []vmItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrappedList); err == nil && wrappedList.Data != nil {
		if wrappedList.Code != 0 {
			return nil, fmt.Errorf("vm list failed: code=%d message=%s", wrappedList.Code, wrappedList.Message)
		}
		return wrappedList.Data, nil
	}

	var wrapped struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
		Data    struct {
			List []vmItem `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("vm list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data.List, nil
}
