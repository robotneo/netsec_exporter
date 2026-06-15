package ac

import (
	"context"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

// CollectSystemMetrics 用于承载 AC 的系统级指标。
// 典型包括 CPU、内存、磁盘、版本、运行时长等。
func CollectSystemMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	version := ""
	up := 0.0
	cpuUsage := 0.0
	memUsage := 0.0
	diskUsage := 0.0

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    string `json:"data"`
	}

	err := c.DoJSON(context.Background(), "/v1/status/version", &resp)
	if err == nil && resp.Code == 0 {
		version = strings.TrimSpace(resp.Data)
		up = 1
	}

	var cpuResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}

	err = c.DoJSON(context.Background(), "/v1/status/cpu-usage", &cpuResp)
	if err == nil && cpuResp.Code == 0 {
		cpuUsage = float64(cpuResp.Data)
	}

	var memResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}

	err = c.DoJSON(context.Background(), "/v1/status/mem-usage", &memResp)
	if err == nil && memResp.Code == 0 {
		memUsage = float64(memResp.Data)
	}

	var diskResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}

	err = c.DoJSON(context.Background(), "/v1/status/disk-usage", &diskResp)
	if err == nil && diskResp.Code == 0 {
		diskUsage = float64(diskResp.Data)
	}

	labels := map[string]string{
		"version": version,
	}

	return []core.Metric{
		{
			Name:   "netsec_system_version_info",
			Value:  up,
			Labels: labels,
		},
		{
			Name:   "netsec_system_cpu_usage_percent",
			Value:  cpuUsage,
			Labels: nil,
		},
		{
			Name:   "netsec_system_memory_usage_percent",
			Value:  memUsage,
			Labels: nil,
		},
		{
			Name:   "netsec_system_disk_usage_percent",
			Value:  diskUsage,
			Labels: nil,
		},
	}, nil
}
