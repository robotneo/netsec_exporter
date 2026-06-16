package ad

import (
	"fmt"
	"strings"
	"time"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

func CollectInterfaceMetrics(dev core.Device) ([]core.Metric, error) {
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

		totalUplinkOID   = ".1.3.6.1.4.1.35047.2.2.5.0"
		totalDownlinkOID = ".1.3.6.1.4.1.35047.2.2.6.0"
		linkNumberOID    = ".1.3.6.1.4.1.35047.2.2.42.0"

		linkNameOID   = ".1.3.6.1.4.1.35047.2.2.41.1.2"
		linkTypeOID   = ".1.3.6.1.4.1.35047.2.2.41.1.3"
		linkIfNameOID = ".1.3.6.1.4.1.35047.2.2.41.1.4"
		linkStateOID  = ".1.3.6.1.4.1.35047.2.2.41.1.5"
		linkBitInOID  = ".1.3.6.1.4.1.35047.2.2.41.1.6"
		linkBitOutOID = ".1.3.6.1.4.1.35047.2.2.41.1.7"
		linkDescrOID  = ".1.3.6.1.4.1.35047.2.2.41.1.8"

		ifSpeedNameOID = ".1.3.6.1.4.1.35047.2.2.7.1.2"
		ifSpeedOID     = ".1.3.6.1.4.1.35047.2.2.7.1.3"

		ifStatNameOID  = ".1.3.6.1.4.1.35047.2.2.43.1.2"
		ifBitInOID     = ".1.3.6.1.4.1.35047.2.2.43.1.3"
		ifBitOutOID    = ".1.3.6.1.4.1.35047.2.2.43.1.4"
		ifPacketInOID  = ".1.3.6.1.4.1.35047.2.2.43.1.5"
		ifPacketOutOID = ".1.3.6.1.4.1.35047.2.2.43.1.6"
		ifErrorInOID   = ".1.3.6.1.4.1.35047.2.2.43.1.7"
		ifErrorOutOID  = ".1.3.6.1.4.1.35047.2.2.43.1.8"
		ifDropInOID    = ".1.3.6.1.4.1.35047.2.2.43.1.9"
		ifDropOutOID   = ".1.3.6.1.4.1.35047.2.2.43.1.10"
	)

	parseIndex := func(baseOID, fullOID string) string {
		idx := strings.TrimPrefix(fullOID, baseOID+".")
		if idx == fullOID {
			idx = strings.TrimPrefix(fullOID, baseOID)
			idx = strings.TrimPrefix(idx, ".")
		}
		return strings.TrimSpace(idx)
	}

	result, err := snmp.Get([]string{sysNameOID, totalUplinkOID, totalDownlinkOID, linkNumberOID})
	if err != nil {
		return nil, err
	}

	sysName := ""
	totalUpBps := 0.0
	totalDownBps := 0.0
	linkTotal := 0.0

	for _, pdu := range result.Variables {
		switch pdu.Name {
		case sysNameOID:
			switch v := pdu.Value.(type) {
			case string:
				sysName = strings.TrimSpace(v)
			case []byte:
				sysName = strings.TrimSpace(string(v))
			}
		case totalUplinkOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				totalUpBps = v * 1000
			}
		case totalDownlinkOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				totalDownBps = v * 1000
			}
		case linkNumberOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				linkTotal = v
			}
		}
	}

	baseLabels := map[string]string{}
	if sysName != "" {
		baseLabels["device_name"] = sysName
	}

	metrics := []core.Metric{
		{
			Name:  "netsec_interface_send_bits",
			Value: totalUpBps,
			Labels: cloneLabels(baseLabels, map[string]string{
				"name": "ALL",
			}),
		},
		{
			Name:  "netsec_interface_recv_bits",
			Value: totalDownBps,
			Labels: cloneLabels(baseLabels, map[string]string{
				"name": "ALL",
			}),
		},
		{
			Name:   "netsec_link_total",
			Value:  linkTotal,
			Labels: baseLabels,
		},
	}

	linkNameByIdx := map[string]string{}
	linkTypeByIdx := map[string]float64{}
	linkIfNameByIdx := map[string]string{}
	linkStateByIdx := map[string]float64{}
	linkBitInByIdx := map[string]float64{}
	linkBitOutByIdx := map[string]float64{}
	linkDescrByIdx := map[string]string{}

	_ = snmp.BulkWalk(linkNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			linkNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			linkNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})
	_ = snmp.BulkWalk(linkTypeOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkTypeOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			linkTypeByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(linkIfNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkIfNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			linkIfNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			linkIfNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})
	_ = snmp.BulkWalk(linkStateOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkStateOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			linkStateByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(linkBitInOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkBitInOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			linkBitInByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(linkBitOutOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkBitOutOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			linkBitOutByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(linkDescrOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(linkDescrOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			linkDescrByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			linkDescrByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})

	linkIndexes := map[string]struct{}{}
	for idx := range linkNameByIdx {
		linkIndexes[idx] = struct{}{}
	}
	for idx := range linkIfNameByIdx {
		linkIndexes[idx] = struct{}{}
	}
	for idx := range linkStateByIdx {
		linkIndexes[idx] = struct{}{}
	}
	for idx := range linkBitInByIdx {
		linkIndexes[idx] = struct{}{}
	}
	for idx := range linkBitOutByIdx {
		linkIndexes[idx] = struct{}{}
	}

	for idx := range linkIndexes {
		labels := cloneLabels(baseLabels, map[string]string{
			"link_index": idx,
			"link_name":  linkNameByIdx[idx],
			"if_name":    linkIfNameByIdx[idx],
			"link_descr": linkDescrByIdx[idx],
		})
		if v, ok := linkTypeByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_link_type",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := linkStateByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_link_oper_state",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := linkBitInByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_link_traffic_in_bps",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := linkBitOutByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_link_traffic_out_bps",
				Value:  v,
				Labels: labels,
			})
		}
	}

	ifNameByIdx := map[string]string{}
	ifSpeedByIdx := map[string]float64{}
	ifStatNameByIdx := map[string]string{}
	ifBitInByIdx := map[string]float64{}
	ifBitOutByIdx := map[string]float64{}
	ifPacketInByIdx := map[string]float64{}
	ifPacketOutByIdx := map[string]float64{}
	ifErrorInByIdx := map[string]float64{}
	ifErrorOutByIdx := map[string]float64{}
	ifDropInByIdx := map[string]float64{}
	ifDropOutByIdx := map[string]float64{}

	_ = snmp.BulkWalk(ifSpeedNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifSpeedNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			ifNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			ifNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})
	_ = snmp.BulkWalk(ifSpeedOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifSpeedOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifSpeedByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifStatNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifStatNameOID, pdu.Name)
		if idx == "" {
			return nil
		}
		switch v := pdu.Value.(type) {
		case string:
			ifStatNameByIdx[idx] = strings.TrimSpace(v)
		case []byte:
			ifStatNameByIdx[idx] = strings.TrimSpace(string(v))
		}
		return nil
	})
	_ = snmp.BulkWalk(ifBitInOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifBitInOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifBitInByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifBitOutOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifBitOutOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifBitOutByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifPacketInOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifPacketInOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifPacketInByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifPacketOutOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifPacketOutOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifPacketOutByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifErrorInOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifErrorInOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifErrorInByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifErrorOutOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifErrorOutOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifErrorOutByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifDropInOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifDropInOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifDropInByIdx[idx] = v
		}
		return nil
	})
	_ = snmp.BulkWalk(ifDropOutOID, func(pdu gosnmp.SnmpPDU) error {
		idx := parseIndex(ifDropOutOID, pdu.Name)
		if idx == "" {
			return nil
		}
		if v, ok := snmpPDUToFloat64(pdu); ok {
			ifDropOutByIdx[idx] = v
		}
		return nil
	})

	ifIndexes := map[string]struct{}{}
	for idx := range ifNameByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifStatNameByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifSpeedByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifBitInByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifBitOutByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifPacketInByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifPacketOutByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifErrorInByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifErrorOutByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifDropInByIdx {
		ifIndexes[idx] = struct{}{}
	}
	for idx := range ifDropOutByIdx {
		ifIndexes[idx] = struct{}{}
	}

	for idx := range ifIndexes {
		ifName := ifNameByIdx[idx]
		if ifName == "" {
			ifName = ifStatNameByIdx[idx]
		}
		labels := cloneLabels(baseLabels, map[string]string{
			"if_name":     ifName,
			"description": "",
			"zone":        "",
			"mac":         "",
			"ip_addr":     "",
			"if_index":    idx,
		})
		if v, ok := ifSpeedByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_speed_mbps",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifBitInByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_in_bits_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifBitOutByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_out_bits_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifPacketInByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_in_packets_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifPacketOutByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_out_packets_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifErrorInByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_in_errors_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifErrorOutByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_out_errors_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifDropInByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_in_drops_total",
				Value:  v,
				Labels: labels,
			})
		}
		if v, ok := ifDropOutByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_out_drops_total",
				Value:  v,
				Labels: labels,
			})
		}
	}

	return metrics, nil
}

func cloneLabels(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
