package ac

import (
	"strings"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

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
