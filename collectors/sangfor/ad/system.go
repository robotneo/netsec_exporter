package ad

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

func CollectSystemMetrics(dev core.Device) ([]core.Metric, error) {
	if strings.TrimSpace(dev.SNMPCommunity) == "" {
		return nil, fmt.Errorf("missing snmp_community")
	}

	host := snmpTargetHost(dev.Host)
	port := dev.SNMPPort
	if port == 0 {
		port = 161
	}

	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      port,
		Community: dev.SNMPCommunity,
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
		Retries:   1,
		MaxOids:   gosnmp.MaxOids,
	}
	if err := snmp.Connect(); err != nil {
		return nil, err
	}
	defer snmp.Conn.Close()

	const (
		sysNameOID = ".1.3.6.1.2.1.1.5.0"

		deviceStatusOID = ".1.3.6.1.4.1.35047.1.12.0"
		adUptimeOID     = ".1.3.6.1.4.1.35047.2.2.46.0"
		cpuUsageOID     = ".1.3.6.1.4.1.35047.1.3.0"
		memUsageOID     = ".1.3.6.1.4.1.35047.2.2.19.0"
		adCpuTempOID    = ".1.3.6.1.4.1.35047.2.2.15.1.13"

		diskPartNameOID = ".1.3.6.1.4.1.35047.1.5.1.2"
		diskUsedPctOID  = ".1.3.6.1.4.1.35047.1.5.1.6"

		fanNameOID  = ".1.3.6.1.4.1.35047.1.14.1.2"
		fanSpeedOID = ".1.3.6.1.4.1.35047.1.14.1.3"
		fanStateOID = ".1.3.6.1.4.1.35047.1.14.1.4"

		powerNameOID  = ".1.3.6.1.4.1.35047.1.15.1.2"
		powerStateOID = ".1.3.6.1.4.1.35047.1.15.1.3"
	)

	result, err := snmp.Get([]string{sysNameOID, deviceStatusOID, adUptimeOID, cpuUsageOID, memUsageOID})
	if err != nil {
		return nil, err
	}

	sysName := ""
	deviceStatus := 0.0
	uptimeSeconds := 0.0
	cpuUsagePercent := 0.0
	memUsagePercent := 0.0
	cpuTempByIdx := map[string]float64{}
	diskPartNameByIdx := map[string]string{}
	diskUsedPctByIdx := map[string]float64{}
	fanNameByIdx := map[string]string{}
	fanSpeedByIdx := map[string]float64{}
	fanStateByIdx := map[string]float64{}
	powerNameByIdx := map[string]string{}
	powerStateByIdx := map[string]float64{}

	for _, pdu := range result.Variables {
		switch pdu.Name {
		case sysNameOID:
			switch v := pdu.Value.(type) {
			case string:
				sysName = strings.TrimSpace(v)
			case []byte:
				sysName = strings.TrimSpace(string(v))
			}
		case deviceStatusOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				deviceStatus = v
			}
		case adUptimeOID:
			if pdu.Type == gosnmp.TimeTicks {
				if v, ok := snmpPDUToFloat64(pdu); ok {
					uptimeSeconds = v / 100
				}
				continue
			}
			if v, ok := snmpPDUToFloat64(pdu); ok {
				uptimeSeconds = v
			}
		case cpuUsageOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				cpuUsagePercent = v
			}
		case memUsageOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				memUsagePercent = v
			}
		}
	}

	parseIndex := func(baseOID, fullOID string) string {
		idx := strings.TrimPrefix(fullOID, baseOID+".")
		if idx == fullOID {
			idx = strings.TrimPrefix(fullOID, baseOID)
			idx = strings.TrimPrefix(idx, ".")
		}
		return strings.TrimSpace(idx)
	}

	_ = snmp.BulkWalk(adCpuTempOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(adCpuTempOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			cpuTempByIdx[idx] = v
		}
		return nil
	})

	labels := map[string]string{}
	if sysName != "" {
		labels["device_name"] = sysName
	}

	metrics := []core.Metric{
		{
			Name:   "netsec_system_device_status",
			Value:  deviceStatus,
			Labels: labels,
		},
		{
			Name:   "netsec_system_cpu_usage_percent",
			Value:  cpuUsagePercent,
			Labels: labels,
		},
		{
			Name:   "netsec_system_memory_usage_percent",
			Value:  memUsagePercent,
			Labels: labels,
		},
		{
			Name:   "netsec_system_uptime_seconds",
			Value:  uptimeSeconds,
			Labels: labels,
		},
	}

	_ = snmp.BulkWalk(diskPartNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(diskPartNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			diskPartNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			diskPartNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})

	_ = snmp.BulkWalk(diskUsedPctOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(diskUsedPctOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			diskUsedPctByIdx[idx] = v
		}
		return nil
	})

	_ = snmp.BulkWalk(fanNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(fanNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			fanNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			fanNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})

	_ = snmp.BulkWalk(fanSpeedOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(fanSpeedOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			fanSpeedByIdx[idx] = v
		}
		return nil
	})

	_ = snmp.BulkWalk(fanStateOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(fanStateOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			fanStateByIdx[idx] = v
		}
		return nil
	})

	_ = snmp.BulkWalk(powerNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(powerNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			powerNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			powerNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})

	_ = snmp.BulkWalk(powerStateOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(powerStateOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			switch v {
			case 2:
				powerStateByIdx[idx] = 1
			case 1:
				powerStateByIdx[idx] = 0
			default:
				powerStateByIdx[idx] = v
			}
		}
		return nil
	})

	for idx, temp := range cpuTempByIdx {
		l := map[string]string{}
		for k, v := range labels {
			l[k] = v
		}
		l["cpu_index"] = idx
		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_cpu_temperature_celsius",
			Value:  temp,
			Labels: l,
		})
	}

	for idx, used := range diskUsedPctByIdx {
		l := map[string]string{}
		for k, v := range labels {
			l[k] = v
		}
		l["disk_index"] = idx
		if partName, ok := diskPartNameByIdx[idx]; ok {
			l["part_name"] = partName
		} else {
			l["part_name"] = ""
		}
		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_disk_usage_percent",
			Value:  used,
			Labels: l,
		})
	}

	for idx, state := range fanStateByIdx {
		l := map[string]string{}
		for k, v := range labels {
			l[k] = v
		}
		l["fan_index"] = idx
		if fanName, ok := fanNameByIdx[idx]; ok {
			l["fan_name"] = fanName
		} else {
			l["fan_name"] = ""
		}
		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_fan_status",
			Value:  state,
			Labels: l,
		})
	}

	for idx, speed := range fanSpeedByIdx {
		l := map[string]string{}
		for k, v := range labels {
			l[k] = v
		}
		l["fan_index"] = idx
		if fanName, ok := fanNameByIdx[idx]; ok {
			l["fan_name"] = fanName
		} else {
			l["fan_name"] = ""
		}
		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_fan_speed_rpm",
			Value:  speed,
			Labels: l,
		})
	}

	for idx, state := range powerStateByIdx {
		l := map[string]string{}
		for k, v := range labels {
			l[k] = v
		}
		l["power_index"] = idx
		if powerName, ok := powerNameByIdx[idx]; ok {
			l["power_name"] = powerName
		} else {
			l["power_name"] = ""
		}
		metrics = append(metrics, core.Metric{
			Name:   "netsec_system_power_status",
			Value:  state,
			Labels: l,
		})
	}

	return metrics, nil
}

func snmpTargetHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return h
	}
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		h = strings.TrimPrefix(h, "http://")
		h = strings.TrimPrefix(h, "https://")
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if strings.Contains(h, ":") {
		parts := strings.Split(h, ":")
		if len(parts) > 0 && strings.TrimSpace(parts[0]) != "" {
			return strings.TrimSpace(parts[0])
		}
	}
	return h
}

func snmpPDUToFloat64(pdu gosnmp.SnmpPDU) (float64, bool) {
	switch v := pdu.Value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	case []byte:
		s := strings.TrimSpace(string(v))
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}
