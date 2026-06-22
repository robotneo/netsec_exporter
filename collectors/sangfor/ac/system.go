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

type acAPIResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func parseACDataFloat(v any) (float64, error) {
	switch x := v.(type) {
	case nil:
		return 0, fmt.Errorf("empty data")
	case float64:
		return x, nil
	case float32:
		return float64(x), nil
	case int:
		return float64(x), nil
	case int8:
		return float64(x), nil
	case int16:
		return float64(x), nil
	case int32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case uint:
		return float64(x), nil
	case uint8:
		return float64(x), nil
	case uint16:
		return float64(x), nil
	case uint32:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	case json.Number:
		return x.Float64()
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return 0, fmt.Errorf("empty data")
		}
		return strconv.ParseFloat(s, 64)
	default:
		return 0, fmt.Errorf("unsupported data type %T", v)
	}
}

func parseACDataString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(x)
	case json.Number:
		return strings.TrimSpace(x.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
}

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

func CollectCPUMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	var resp acAPIResponse
	if err := c.DoJSON(context.Background(), "/v1/status/cpu-usage", &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("cpu usage failed: code=%d message=%s", resp.Code, resp.Message)
	}

	v, err := parseACDataFloat(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("cpu usage parse failed: %w", err)
	}

	return []core.Metric{
		{
			Name:  "netsec_system_cpu_usage_percent",
			Value: v,
		},
	}, nil
}

func CollectMemoryMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	var resp acAPIResponse
	if err := c.DoJSON(context.Background(), "/v1/status/mem-usage", &resp); err != nil {
		return nil, err
	}
	if resp.Code != 0 {
		return nil, fmt.Errorf("memory usage failed: code=%d message=%s", resp.Code, resp.Message)
	}

	v, err := parseACDataFloat(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("memory usage parse failed: %w", err)
	}

	return []core.Metric{
		{
			Name:  "netsec_system_memory_usage_percent",
			Value: v,
		},
	}, nil
}

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
