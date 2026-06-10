package firewall

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

var uptimePartPattern = regexp.MustCompile(`(\d+)\s*(天|小时|分钟|分|秒)`)

func CollectUptimeSeconds(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	apiURL := fmt.Sprintf("https://%s/api/v1/namespaces/%s/uptimes", dev.Host, sess.Namespace)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AuthorizationToken", sess.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/uptimes", dev.Host)
		req, err = http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("AuthorizationToken", sess.Token)
		resp, err = c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("uptimes api status code: %d", resp.StatusCode)
	}

	var ur struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			UpTimes string `json:"upTimes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ur); err != nil {
		return nil, err
	}
	if ur.Code != 0 {
		return nil, fmt.Errorf("uptimes failed: code=%d message=%s", ur.Code, ur.Message)
	}

	seconds, err := parseUptimeToSeconds(ur.Data.UpTimes)
	if err != nil {
		return nil, err
	}

	bootTime := float64(time.Now().Unix()) - seconds

	return []core.Metric{
		{
			Name:  "netsec_system_uptime_seconds",
			Value: seconds,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"type":        dev.Type,
			},
		},
		{
			Name:  "netsec_system_boot_time_seconds",
			Value: bootTime,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"type":        dev.Type,
			},
		},
	}, nil
}

func parseUptimeToSeconds(raw string) (float64, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, fmt.Errorf("uptime is empty")
	}

	matches := uptimePartPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("unsupported uptime format: %s", text)
	}

	var total float64
	for _, m := range matches {
		if len(m) != 3 {
			continue
		}

		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, fmt.Errorf("invalid uptime number: %w", err)
		}

		switch m[2] {
		case "天":
			total += float64(n * 24 * 3600)
		case "小时":
			total += float64(n * 3600)
		case "分钟", "分":
			total += float64(n * 60)
		case "秒":
			total += float64(n)
		default:
			return 0, fmt.Errorf("unsupported uptime unit: %s", m[2])
		}
	}

	condensed := strings.ReplaceAll(text, " ", "")
	reconstructed := ""
	for _, m := range matches {
		reconstructed += strings.ReplaceAll(strings.TrimSpace(m[0]), " ", "")
	}
	if reconstructed != condensed {
		return 0, fmt.Errorf("unsupported uptime format: %s", text)
	}

	return total, nil
}
