package hci

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"netsec_exporter/collectors/sangfor/client"
)

func doList(ctx context.Context, c *client.HCIClient, sess client.HCISession, primaryPath string, fallbackPath string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := c.DoJSON(ctx, sess, "GET", primaryPath, nil, &raw)
	if err == nil {
		return raw, nil
	}
	if fallbackPath == "" {
		return nil, err
	}
	if strings.Contains(err.Error(), "status=404") {
		var raw2 json.RawMessage
		if e := c.DoJSON(ctx, sess, "GET", fallbackPath, nil, &raw2); e == nil {
			return raw2, nil
		} else {
			return nil, e
		}
	}
	return nil, err
}

func cloneLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func bytesFactor(unit string) (float64, bool) {
	u := strings.ToLower(strings.TrimSpace(unit))
	switch u {
	case "b", "byte", "bytes":
		return 1, true
	case "kb", "kib":
		return 1024, true
	case "mb", "mib":
		return 1024 * 1024, true
	case "gb", "gib":
		return 1024 * 1024 * 1024, true
	case "tb", "tib":
		return 1024 * 1024 * 1024 * 1024, true
	default:
		return 0, false
	}
}

func hzFactor(unit string) (float64, bool) {
	u := strings.ToLower(strings.TrimSpace(unit))
	switch u {
	case "hz":
		return 1, true
	case "khz":
		return 1_000, true
	case "mhz":
		return 1_000_000, true
	case "ghz":
		return 1_000_000_000, true
	default:
		return 0, false
	}
}

func TokenSession(token string) client.HCISession {
	return client.HCISession{
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LoginAt:   time.Now(),
	}
}
