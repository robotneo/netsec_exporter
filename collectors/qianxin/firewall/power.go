package firewall

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectPowerMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	resp, err := fetchSystemResource(context.Background(), c, sess, dev)
	if err != nil {
		return nil, err
	}
	return buildPowerMetrics(resp)
}

func buildPowerMetrics(resp qianxinSystemResourceResponse) ([]core.Metric, error) {
	metrics := make([]core.Metric, 0, len(resp.Data.Power)+1)

	for idx, power := range resp.Data.Power {
		powerName := strings.TrimSpace(power.Name)
		if powerName == "" {
			powerName = fmt.Sprintf("power%d", idx)
		}

		metrics = append(metrics, core.Metric{
			Name:  "netsec_system_power_status",
			Value: mapPowerState(power.State),
			Labels: map[string]string{
				"entity_name": powerName,
			},
		})
	}

	if watts, ok := parsePowerCapacityWatts(resp.Data.PowerSupply.Capacity); ok {
		powerName := "power_supply"
		if len(resp.Data.Power) == 1 {
			if name := strings.TrimSpace(resp.Data.Power[0].Name); name != "" {
				powerName = name
			}
		}
		metrics = append(metrics, core.Metric{
			Name:  "netsec_system_power_capacity_watts",
			Value: watts,
			Labels: map[string]string{
				"entity_name": powerName,
			},
		})
	}

	if len(metrics) == 0 {
		return nil, fmt.Errorf("power data not found in response")
	}
	return metrics, nil
}

func mapPowerState(state string) float64 {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "true", "ok", "normal", "on", "running":
		return 1
	default:
		return 0
	}
}

func parsePowerCapacityWatts(raw string) (float64, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, "W")
	s = strings.TrimSuffix(s, "w")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}

	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
