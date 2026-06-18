package firewall

import (
	"context"
	"fmt"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectCPUMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemResource(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}
	return buildCPUMetrics(resp)
}

func buildCPUMetrics(resp qianxinSystemResourceResponse) ([]core.Metric, error) {
	if len(resp.Data.CPU) == 0 {
		return nil, fmt.Errorf("cpu usage not found in response")
	}

	metrics := make([]core.Metric, 0, len(resp.Data.CPU))
	for idx, cpu := range resp.Data.CPU {
		cpuName := strings.TrimSpace(cpu.Name)
		if cpuName == "" {
			cpuName = fmt.Sprintf("cpu%d", idx)
		}
		metrics = append(metrics, core.Metric{
			Name:  "netsec_system_cpu_usage_percent",
			Value: cpu.Useage,
			Labels: map[string]string{
				"entity_name": cpuName,
			},
		})
	}

	return metrics, nil
}
