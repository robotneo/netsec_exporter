package firewall

import (
	"fmt"
	"strings"
	"time"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

const (
	dbappMemTotalKBOID     = ".1.3.6.1.4.1.38384.4.2.2.2.3.0"
	dbappMemFreeKBOID      = ".1.3.6.1.4.1.38384.4.2.2.2.4.0"
	dbappMemAvailableKBOID = ".1.3.6.1.4.1.38384.4.2.2.2.5.0"
	dbappMemUsedPercentOID = ".1.3.6.1.4.1.38384.4.2.2.2.8.0"
)

func CollectMemoryUsagePercentSNMP(dev core.Device, timeout time.Duration) ([]core.Metric, error) {
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
		dbappMemUsedPercentOID,
		dbappMemTotalKBOID,
		dbappMemAvailableKBOID,
		dbappMemFreeKBOID,
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

	usedPercent, hasUsedPercent := values[dbappMemUsedPercentOID]
	totalKB, hasTotal := values[dbappMemTotalKBOID]
	availKB, hasAvail := values[dbappMemAvailableKBOID]
	freeKB, hasFree := values[dbappMemFreeKBOID]

	var memUsage float64
	switch {
	case hasUsedPercent:
		memUsage = usedPercent
	case hasTotal && totalKB > 0 && hasAvail:
		memUsage = (1 - (availKB / totalKB)) * 100
	case hasTotal && totalKB > 0 && hasFree:
		memUsage = (1 - (freeKB / totalKB)) * 100
	default:
		return nil, fmt.Errorf("snmp memory oid values missing")
	}

	if memUsage < 0 {
		memUsage = 0
	}
	if memUsage > 100 {
		memUsage = 100
	}

	return []core.Metric{
		{
			Name:  "netsec_memory_usage_percent",
			Value: memUsage,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"role":        dev.Type,
			},
		},
	}, nil
}
