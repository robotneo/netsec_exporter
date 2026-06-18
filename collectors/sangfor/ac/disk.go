package ac

import (
	"context"
	"fmt"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectDiskMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	var resp acAPIResponse
	if err := c.DoJSON(context.Background(), "/v1/status/disk-usage", &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("disk usage failed: code=%d message=%s", resp.Code, resp.Message)
	}

	v, err := parseACDataFloat(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("disk usage parse failed: %w", err)
	}

	return []core.Metric{
		{
			Name:  "netsec_system_disk_usage_percent",
			Value: v,
		},
	}, nil
}
