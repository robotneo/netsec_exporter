package ac

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

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
