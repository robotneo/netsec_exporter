package ac

import (
	"context"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

// CollectUserMetrics 用于承载 AC 的用户与终端相关指标。
// 典型包括在线用户数、认证用户数、在线终端数等。
func CollectUserMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	onlineUsers := 0.0

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}

	err := c.DoJSON(context.Background(), "/v1/status/online-user", &resp)
	if err == nil && resp.Code == 0 {
		onlineUsers = float64(resp.Data)
	}

	return []core.Metric{
		{
			Name:   "netsec_online_users_current",
			Value:  onlineUsers,
			Labels: nil,
		},
	}, nil
}
