package ac

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

var uptimePartPattern = regexp.MustCompile(`(?i)(\d+)\s*(weeks?|days?|hours?|minutes?|mins?|seconds?|secs?|天|小时|分钟|分|秒)`)

func appendMetricGroups(groups ...[]core.Metric) []core.Metric {
	var out []core.Metric
	for _, group := range groups {
		out = append(out, group...)
	}
	return out
}

func snmpTargetHost(host string) string {
	h := strings.TrimSpace(host)
	if strings.Count(h, ":") == 1 {
		parts := strings.Split(h, ":")
		h = parts[0]
	}
	return h
}

func snmpPDUToFloat64(pdu gosnmp.SnmpPDU) (float64, bool) {
	switch v := pdu.Value.(type) {
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		bi := gosnmp.ToBigInt(pdu.Value)
		if bi == nil {
			return 0, false
		}
		f, _ := bi.Float64()
		return f, true
	}
}

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

func parseUptimeToSeconds(raw string) (float64, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, fmt.Errorf("uptime is empty")
	}

	matches := uptimePartPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		if v, err := strconv.ParseFloat(text, 64); err == nil {
			return v, nil
		}
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

		unit := strings.ToLower(m[2])
		switch unit {
		case "week", "weeks":
			total += float64(n * 7 * 24 * 3600)
		case "day", "days":
			total += float64(n * 24 * 3600)
		case "hour", "hours":
			total += float64(n * 3600)
		case "minute", "minutes", "min", "mins":
			total += float64(n * 60)
		case "second", "seconds", "sec", "secs":
			total += float64(n)
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

	condensed := strings.NewReplacer(" ", "", ",", "", "，", "").Replace(text)
	var reconstructed strings.Builder
	for _, m := range matches {
		reconstructed.WriteString(strings.NewReplacer(" ", "", ",", "", "，", "").Replace(strings.TrimSpace(m[0])))
	}
	if reconstructed.String() != condensed {
		return 0, fmt.Errorf("unsupported uptime format: %s", text)
	}

	return total, nil
}
