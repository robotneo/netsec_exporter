package firewall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

func CollectConcurrentSessions(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	return collectSessionNumber(c, sess, dev, "CONCURRENT", "netsec_session_concurrent")
}

func CollectNewSessions(c *client.Client, sess client.Session, dev core.Device) ([]core.Metric, error) {
	return collectSessionNumber(c, sess, dev, "NEW", "netsec_session_creation_rate")
}

func collectSessionNumber(c *client.Client, sess client.Session, dev core.Device, sessionType string, metricName string) ([]core.Metric, error) {
	apiPath := fmt.Sprintf("/api/v1/namespaces/%s/sessionnumbers?sessionType=%s&timeFilter=REAL-TIME", sess.Namespace, sessionType)
	apiURL := fmt.Sprintf("https://%s%s", dev.Host, apiPath)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("AuthorizationToken", sess.Token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		apiURL = fmt.Sprintf("https://%s/api/v1/namespaces/@namespace/sessionnumbers?sessionType=%s&timeFilter=REAL-TIME", dev.Host, sessionType)
		req, err = http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("AuthorizationToken", sess.Token)

		resp, err = c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sessionnumbers api status code: %d", resp.StatusCode)
	}

	var sr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			SessionNumbers []sessionPoint `json:"sessionNumbers"`
		} `json:"data"`
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body = stripToFirstJSONObject(body)

	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&sr); err != nil {
		return nil, err
	}
	if sr.Code != 0 {
		return nil, fmt.Errorf("sessionnumbers failed: code=%d message=%s", sr.Code, sr.Message)
	}

	value, ok := latestSessionNumber(sr.Data.SessionNumbers)
	if !ok {
		return nil, fmt.Errorf("sessionnumbers empty")
	}

	return []core.Metric{
		{
			Name:  metricName,
			Value: value,
			Labels: map[string]string{
				"device": dev.Name,
				"vendor": dev.Vendor,
				"type":   dev.Type,
			},
		},
	}, nil
}

type sessionPoint struct {
	SessionNumber float64 `json:"sessionNumber"`
	Time          string  `json:"time"`
}

func latestSessionNumber(points []sessionPoint) (float64, bool) {
	if len(points) == 0 {
		return 0, false
	}

	layout := "2006-01-02 15:04:05"
	var (
		bestTime time.Time
		bestVal  float64
		hasBest  bool
	)

	for _, p := range points {
		t, err := time.ParseInLocation(layout, strings.TrimSpace(p.Time), time.Local)
		if err != nil {
			continue
		}
		if !hasBest || t.After(bestTime) {
			bestTime = t
			bestVal = p.SessionNumber
			hasBest = true
		}
	}

	if hasBest {
		return bestVal, true
	}

	last := points[len(points)-1]
	return last.SessionNumber, true
}

func stripToFirstJSONObject(b []byte) []byte {
	i := bytes.IndexByte(b, '{')
	if i < 0 {
		return b
	}
	return b[i:]
}
