package ac

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

// CollectTrafficMetrics 用于承载 AC 的流量与带宽相关指标。
// 典型包括总上下行流量、带宽、应用流量等。
func CollectTrafficMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	labels := map[string]string{
		"name": "WAN",
	}

	var resp struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}

	if err := c.DoJSONPost(context.Background(), "/v1/status/throughput?_method=GET", nil, &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("throughput failed: code=%d message=%s", resp.Code, resp.Message)
	}

	outBits := pickRateBitsPerSecond(resp.Data, []string{"up", "uplink", "upstream", "send", "tx", "out"})
	inBits := pickRateBitsPerSecond(resp.Data, []string{"down", "downlink", "downstream", "recv", "rx", "in"})

	bandwidthUsage := 0.0
	var bwResp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}
	if err := c.DoJSON(context.Background(), "/v1/status/bandwidth-usage", &bwResp); err == nil && bwResp.Code == 0 {
		bandwidthUsage = float64(bwResp.Data)
	}

	return []core.Metric{
		{Name: "netsec_interface_send_bits", Value: outBits, Labels: labels},
		{Name: "netsec_interface_recv_bits", Value: inBits, Labels: labels},
		{Name: "netsec_bandwidth_usage_percent", Value: bandwidthUsage, Labels: labels},
	}, nil
}

func pickRateBitsPerSecond(m map[string]any, keys []string) float64 {
	if m == nil {
		return 0
	}
	lower := map[string]any{}
	for k, v := range m {
		lower[strings.ToLower(strings.TrimSpace(k))] = v
	}
	for _, k := range keys {
		if v, ok := lower[k]; ok {
			return parseRateBitsPerSecond(v)
		}
	}
	return 0
}

func parseRateBitsPerSecond(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x * 8
	case float32:
		return float64(x) * 8
	case int:
		return float64(x) * 8
	case int64:
		return float64(x) * 8
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0
		}
		return f * 8
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0
		}
		l := strings.ToLower(s)
		parseNum := func(num string) float64 {
			f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
			if err != nil {
				return 0
			}
			return f
		}

		switch {
		case strings.HasSuffix(l, "gb/s"):
			return parseNum(s[:len(s)-4]) * 1e9 * 8
		case strings.HasSuffix(l, "mb/s"):
			return parseNum(s[:len(s)-4]) * 1e6 * 8
		case strings.HasSuffix(l, "kb/s"):
			return parseNum(s[:len(s)-4]) * 1e3 * 8
		case strings.HasSuffix(l, "b/s"):
			return parseNum(s[:len(s)-3]) * 8
		case strings.HasSuffix(l, "gbps"):
			return parseNum(s[:len(s)-4]) * 1e9
		case strings.HasSuffix(l, "mbps"):
			return parseNum(s[:len(s)-4]) * 1e6
		case strings.HasSuffix(l, "kbps"):
			return parseNum(s[:len(s)-4]) * 1e3
		case strings.HasSuffix(l, "bps"):
			return parseNum(s[:len(s)-3])
		default:
			return parseNum(s) * 8
		}
	default:
		return 0
	}
}
