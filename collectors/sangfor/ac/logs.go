package ac

import (
	"context"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

// CollectLogMetrics 用于承载 AC 的行为日志相关指标。
func CollectLogMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	block := 0.0
	record := 0.0

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Block  int64 `json:"block"`
			Record int64 `json:"record"`
		} `json:"data"`
	}

	err := c.DoJSON(context.Background(), "/v1/status/log", &resp)
	if err == nil && resp.Code == 0 {
		block = float64(resp.Data.Block)
		record = float64(resp.Data.Record)
	}

	return []core.Metric{
		{
			Name:   "netsec_behavior_log_block_current",
			Value:  block,
			Labels: nil,
		},
		{
			Name:   "netsec_behavior_log_record_current",
			Value:  record,
			Labels: nil,
		},
	}, nil
}
