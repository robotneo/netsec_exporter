package ac

import (
	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectSystemMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	var metrics []core.Metric
	var lastErr error

	for _, collect := range []func(*client.ACClient, core.Device) ([]core.Metric, error){
		CollectVersionMetrics,
		CollectCPUMetrics,
		CollectMemoryMetrics,
		CollectDiskMetrics,
	} {
		ms, err := collect(c, dev)
		if err != nil {
			lastErr = err
			continue
		}
		metrics = append(metrics, ms...)
	}

	if len(metrics) > 0 {
		return metrics, nil
	}
	return nil, lastErr
}
