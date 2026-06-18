package ac

import (
	"context"
	"fmt"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectUptimeMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	paths := []string{
		"/v1/status/uptime",
		"/v1/status/up-time",
		"/v1/status/runtime",
		"/v1/status/run-time",
	}

	var lastErr error
	for _, path := range paths {
		var resp acAPIResponse
		if err := c.DoJSON(context.Background(), path, &resp); err != nil {
			lastErr = err
			continue
		}
		if resp.Code != 0 {
			lastErr = fmt.Errorf("uptime failed: code=%d message=%s", resp.Code, resp.Message)
			continue
		}

		seconds, err := parseUptimeToSeconds(parseACDataString(resp.Data))
		if err != nil {
			lastErr = err
			continue
		}

		return []core.Metric{
			{
				Name:  "netsec_system_uptime_seconds",
				Value: seconds,
			},
		}, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("uptime not available")
	}
	return nil, lastErr
}
