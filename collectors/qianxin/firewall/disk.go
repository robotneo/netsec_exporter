package firewall

import (
	"context"
	"fmt"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectDiskMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemResource(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}
	return buildDiskMetrics(resp)
}

func buildDiskMetrics(resp qianxinSystemResourceResponse) ([]core.Metric, error) {
	disks := []struct {
		name string
		data qianxinSystemResourceDisk
	}{
		{name: "cf", data: resp.Data.CF},
		{name: "ssd", data: resp.Data.SSD},
	}

	metrics := make([]core.Metric, 0, len(disks))
	for _, disk := range disks {
		if disk.data.Total <= 0 && disk.data.Use <= 0 && disk.data.Free <= 0 && disk.data.Useage <= 0 {
			continue
		}
		metrics = append(metrics, core.Metric{
			Name:  "netsec_system_disk_usage_percent",
			Value: disk.data.Useage,
			Labels: map[string]string{
				"entity_name": strings.TrimSpace(disk.name),
			},
		})
	}

	if len(metrics) == 0 {
		return nil, fmt.Errorf("disk usage not found in response")
	}
	return metrics, nil
}
