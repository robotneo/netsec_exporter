package ac

import (
	"context"
	"fmt"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectVersionMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	var resp acAPIResponse
	if err := c.DoJSON(context.Background(), "/v1/status/version", &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("version failed: code=%d message=%s", resp.Code, resp.Message)
	}

	version := parseACDataString(resp.Data)
	if version == "" {
		return nil, fmt.Errorf("version is empty")
	}

	return []core.Metric{
		{
			Name:   "netsec_system_version_info",
			Value:  1,
			Labels: map[string]string{"version": version},
		},
	}, nil
}
