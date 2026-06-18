package firewall

import (
	"context"
	"fmt"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectFanMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemResource(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}
	return buildFanMetrics(resp)
}

func buildFanMetrics(resp qianxinSystemResourceResponse) ([]core.Metric, error) {
	if len(resp.Data.Fan) == 0 {
		return nil, fmt.Errorf("fan data not found in response")
	}

	metrics := make([]core.Metric, 0, len(resp.Data.Fan)*2)
	for idx, fan := range resp.Data.Fan {
		fanName := strings.TrimSpace(fan.Name)
		if fanName == "" {
			fanName = fmt.Sprintf("fan%d", idx)
		}

		labels := map[string]string{
			"entity_name": fanName,
		}
		metrics = append(metrics,
			core.Metric{Name: "netsec_system_fan_status", Value: mapFanStatus(fan.Status, fan.Flag), Labels: map[string]string{"entity_name": labels["entity_name"]}},
			core.Metric{Name: "netsec_system_fan_speed_rpm", Value: fan.Speed, Labels: map[string]string{"entity_name": labels["entity_name"]}},
		)
	}

	return metrics, nil
}

func mapFanStatus(status string, flag int) float64 {
	if flag != 0 {
		return 0
	}

	switch strings.ToLower(strings.TrimSpace(status)) {
	case "true", "ok", "normal", "on", "running":
		return 1
	default:
		return 0
	}
}
