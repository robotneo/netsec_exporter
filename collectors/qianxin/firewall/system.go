package firewall

import (
	"context"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func CollectSystemMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	var metrics []core.Metric
	var lastErr error
	hostname := ""

	if ms, host, err := CollectSystemInfoMetrics(c, sess, dev); err == nil {
		metrics = append(metrics, ms...)
		hostname = host
	} else {
		lastErr = err
	}

	if resp, err := fetchSystemResource(context.Background(), c, sess, dev); err == nil {
		for _, collect := range []func(qianxinSystemResourceResponse) ([]core.Metric, error){
			buildCPUMetrics,
			buildMemoryMetrics,
			buildDiskMetrics,
		} {
			if ms, collectErr := collect(resp); collectErr == nil {
				applyHostnameLabel(ms, hostname)
				metrics = append(metrics, ms...)
			} else {
				lastErr = collectErr
			}
		}
	} else {
		lastErr = err
	}

	if len(metrics) > 0 {
		return metrics, nil
	}
	return nil, lastErr
}

func CollectSystemInfoMetrics(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, string, error) {
	resp, err := fetchSystemInfo(context.Background(), c, sess, dev)
	if err != nil {
		return nil, "", err
	}

	hostname := strings.TrimSpace(resp.Data.Hostname)
	baseLabels := map[string]string{}
	if hostname != "" {
		baseLabels["hostname"] = hostname
	}

	metrics := []core.Metric{}
	if version := strings.TrimSpace(resp.Data.Version); version != "" {
		labels := map[string]string{}
		if hostname != "" {
			labels["hostname"] = hostname
		}
		labels["version"] = version
		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_version_info",
			Value:  1,
			Labels: labels,
		})
	}

	return metrics, hostname, nil
}

func fetchSystemInfo(ctx context.Context, c *client.Client, sess client.Session, dev core.Device) (qianxinSystemInfoResponse, error) {
	req := []client.RESTRequest{
		{
			Head: client.RESTHead{
				Function:  "get_system_info",
				Module:    "dashboard",
				PageIndex: 1,
				PageSize:  50,
			},
			Body: client.RESTBody{},
		},
	}

	var resp qianxinSystemInfoResponse
	if err := c.PostREST(ctx, dev, sess, req, &resp); err != nil {
		return qianxinSystemInfoResponse{}, err
	}
	if err := client.EnsureRESTOK("get_system_info", resp.Head); err != nil {
		return qianxinSystemInfoResponse{}, err
	}
	return resp, nil
}

type qianxinSystemInfoResponse struct {
	Head client.RESTResponseHead `json:"head"`
	Data struct {
		Hostname string `json:"hostname"`
		HA       string `json:"ha"`
		Version  string `json:"version"`
	} `json:"data"`
}

func applyHostnameLabel(metrics []core.Metric, hostname string) {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return
	}
	for i := range metrics {
		if metrics[i].Labels == nil {
			metrics[i].Labels = map[string]string{}
		}
		if _, ok := metrics[i].Labels["hostname"]; !ok {
			metrics[i].Labels["hostname"] = hostname
		}
	}
}
