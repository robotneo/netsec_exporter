package firewall

import (
	"fmt"
	"strings"
	"time"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

const (
	dbappCPUUserPercentOID   = ".1.3.6.1.4.1.38384.4.2.2.1.5.0"
	dbappCPUSystemPercentOID = ".1.3.6.1.4.1.38384.4.2.2.1.6.0"
	dbappCPUIdlePercentOID   = ".1.3.6.1.4.1.38384.4.2.2.1.7.0"
)

func CollectCPUUsagePercentSNMP(dev core.Device, timeout time.Duration) ([]core.Metric, error) {
	if strings.TrimSpace(dev.SNMPCommunity) == "" {
		return nil, fmt.Errorf("missing snmp_community")
	}

	port := dev.SNMPPort
	if port == 0 {
		port = 161
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	snmp := &gosnmp.GoSNMP{
		Target:    dev.Host,
		Port:      port,
		Community: dev.SNMPCommunity,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
		MaxOids:   gosnmp.MaxOids,
	}
	if err := snmp.Connect(); err != nil {
		return nil, err
	}
	defer snmp.Conn.Close()

	result, err := snmp.Get([]string{
		dbappCPUUserPercentOID,
		dbappCPUSystemPercentOID,
		dbappCPUIdlePercentOID,
	})
	if err != nil {
		return nil, err
	}

	values := map[string]float64{}
	for _, pdu := range result.Variables {
		val, ok := snmpPDUToFloat64(pdu)
		if !ok {
			continue
		}
		values[pdu.Name] = val
	}

	userVal, hasUser := values[dbappCPUUserPercentOID]
	systemVal, hasSystem := values[dbappCPUSystemPercentOID]
	idleVal, hasIdle := values[dbappCPUIdlePercentOID]

	var cpuUsage float64
	switch {
	case hasUser && hasSystem:
		cpuUsage = userVal + systemVal
	case hasIdle:
		cpuUsage = 100 - idleVal
	default:
		return nil, fmt.Errorf("snmp cpu oid values missing")
	}

	if cpuUsage < 0 {
		cpuUsage = 0
	}
	if cpuUsage > 100 {
		cpuUsage = 100
	}

	return []core.Metric{
		{
			Name:  "netsec_cpu_usage_percent",
			Value: cpuUsage,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"role":        dev.Type,
			},
		},
	}, nil
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
