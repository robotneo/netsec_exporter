package firewall

import (
	"context"
	"fmt"
	"math"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectMemoryMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemResource(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}
	return buildMemoryMetrics(resp)
}

func buildMemoryMetrics(resp qianxinSystemResourceResponse) ([]core.Metric, error) {
	metrics := make([]core.Metric, 0, len(resp.Data.MemoryCores)+3)
	foundUsage := false

	for idx, memoryCore := range resp.Data.MemoryCores {
		memoryName := strings.TrimSpace(memoryCore.Name)
		if memoryName == "" {
			memoryName = fmt.Sprintf("memory%d", idx)
		}
		metrics = append(metrics, core.Metric{
			Name:  "netsec_system_memory_usage_percent",
			Value: memoryCore.Useage,
			Labels: map[string]string{
				"entity_name": memoryName,
			},
		})
		foundUsage = true
	}

	totalBytes := kibToBytes(resp.Data.Memery.Total)
	if totalBytes > 0 {
		memoryName := overallMemoryName(resp)
		usedBytes := math.Round(totalBytes * resp.Data.Memery.Useage / 100)
		freeBytes := totalBytes - usedBytes
		if freeBytes < 0 {
			freeBytes = 0
		}

		labels := map[string]string{
			"entity_name": memoryName,
		}
		metrics = append(metrics,
			core.Metric{Name: "netsec_system_memory_total_bytes", Value: totalBytes, Labels: map[string]string{"entity_name": labels["entity_name"]}},
			core.Metric{Name: "netsec_system_memory_used_bytes", Value: usedBytes, Labels: map[string]string{"entity_name": labels["entity_name"]}},
			core.Metric{Name: "netsec_system_memory_free_bytes", Value: freeBytes, Labels: map[string]string{"entity_name": labels["entity_name"]}},
		)
	}

	if !foundUsage {
		if resp.Data.Memery.Total <= 0 && resp.Data.Memery.Useage <= 0 {
			return nil, fmt.Errorf("memory usage not found in response")
		}
		metrics = append(metrics, core.Metric{
			Name:  "netsec_system_memory_usage_percent",
			Value: resp.Data.Memery.Useage,
			Labels: map[string]string{
				"entity_name": overallMemoryName(resp),
			},
		})
	}

	return metrics, nil
}

func overallMemoryName(resp qianxinSystemResourceResponse) string {
	for _, memoryCore := range resp.Data.MemoryCores {
		if strings.EqualFold(strings.TrimSpace(memoryCore.Name), "system") {
			return strings.TrimSpace(memoryCore.Name)
		}
	}
	return "system"
}

func kibToBytes(v float64) float64 {
	return v * 1024
}
