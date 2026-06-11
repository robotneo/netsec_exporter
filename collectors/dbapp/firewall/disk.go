package firewall

import (
	"fmt"
	"strings"
	"time"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

const (
	dbappDiskNameOID        = ".1.3.6.1.4.1.38384.4.2.2.4.2.1.2"
	dbappDiskTotalSizeKBOID = ".1.3.6.1.4.1.38384.4.2.2.4.2.1.3"
	dbappDiskUsedSizeKBOID  = ".1.3.6.1.4.1.38384.4.2.2.4.2.1.4"
)

type dbappDiskRow struct {
	Name    string
	TotalKB float64
	UsedKB  float64
}

func CollectDiskUsagePercentSNMP(dev core.Device, timeout time.Duration) ([]core.Metric, error) {
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

	rows := map[string]*dbappDiskRow{}

	if err := snmp.BulkWalk(dbappDiskNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx, ok := snmpTableIndex(pdu.Name, dbappDiskNameOID)
		if !ok {
			return nil
		}
		row := rows[idx]
		if row == nil {
			row = &dbappDiskRow{}
			rows[idx] = row
		}
		if s, ok := pdu.Value.(string); ok {
			row.Name = s
		} else {
			row.Name = fmt.Sprintf("%v", pdu.Value)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := snmp.BulkWalk(dbappDiskTotalSizeKBOID, func(pdu gosnmp.SnmpPDU) error {
		idx, ok := snmpTableIndex(pdu.Name, dbappDiskTotalSizeKBOID)
		if !ok {
			return nil
		}
		row := rows[idx]
		if row == nil {
			row = &dbappDiskRow{}
			rows[idx] = row
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			row.TotalKB = v
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := snmp.BulkWalk(dbappDiskUsedSizeKBOID, func(pdu gosnmp.SnmpPDU) error {
		idx, ok := snmpTableIndex(pdu.Name, dbappDiskUsedSizeKBOID)
		if !ok {
			return nil
		}
		row := rows[idx]
		if row == nil {
			row = &dbappDiskRow{}
			rows[idx] = row
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			row.UsedKB = v
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var totalKB float64
	var usedKB float64
	for _, row := range rows {
		if row == nil {
			continue
		}
		if row.TotalKB <= 0 {
			continue
		}
		if row.UsedKB < 0 {
			continue
		}
		totalKB += row.TotalKB
		usedKB += row.UsedKB
	}

	if totalKB <= 0 {
		return nil, fmt.Errorf("snmp disk total size is 0")
	}

	usage := (usedKB / totalKB) * 100
	if usage < 0 {
		usage = 0
	}
	if usage > 100 {
		usage = 100
	}

	return []core.Metric{
		{
			Name:  "netsec_disk_usage_percent",
			Value: usage,
			Labels: map[string]string{
				"device_name": dev.Name,
				"vendor":      dev.Vendor,
				"role":        dev.Type,
			},
		},
	}, nil
}

func snmpTableIndex(fullOID string, baseOID string) (string, bool) {
	full := strings.TrimPrefix(strings.TrimSpace(fullOID), ".")
	base := strings.TrimPrefix(strings.TrimSpace(baseOID), ".")
	if base == "" || full == "" {
		return "", false
	}
	if !strings.HasPrefix(full, base+".") {
		return "", false
	}
	idx := strings.TrimPrefix(full, base+".")
	if idx == "" {
		return "", false
	}
	return idx, true
}
