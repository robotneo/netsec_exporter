package ac

import (
	"fmt"
	"strings"
	"time"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

// CollectInterfaceMetrics 用于承载 AC 的接口相关指标。
// 典型包括接口状态、接口流量、协商速率、接口配置等。
func CollectInterfaceMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	_ = c

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
		ifNameOID = ".1.3.6.1.4.1.35047.2.1.2.1.2"
		ifLinkOID = ".1.3.6.1.4.1.35047.2.1.2.1.4"
		ifTxOID   = ".1.3.6.1.4.1.35047.2.1.2.1.7"
		ifRxOID   = ".1.3.6.1.4.1.35047.2.1.2.1.8"
	)

	ifNameByIdx := map[string]string{}
	linkByIdx := map[string]float64{}
	txBytesByIdx := map[string]float64{}
	rxBytesByIdx := map[string]float64{}

	if err := snmp.BulkWalk(ifNameOID, func(pdu gosnmp.SnmpPDU) error {
		idx := strings.TrimPrefix(pdu.Name, ifNameOID+".")
		if idx == pdu.Name {
			idx = strings.TrimPrefix(pdu.Name, ifNameOID)
			idx = strings.TrimPrefix(idx, ".")
		}
		if idx == "" {
			return nil
		}
		if s, ok := pdu.Value.(string); ok {
			ifNameByIdx[idx] = strings.TrimSpace(s)
		} else if b, ok := pdu.Value.([]byte); ok {
			ifNameByIdx[idx] = strings.TrimSpace(string(b))
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := snmp.BulkWalk(ifLinkOID, func(pdu gosnmp.SnmpPDU) error {
		idx := strings.TrimPrefix(pdu.Name, ifLinkOID+".")
		if idx == pdu.Name {
			idx = strings.TrimPrefix(pdu.Name, ifLinkOID)
			idx = strings.TrimPrefix(idx, ".")
		}
		if idx == "" {
			return nil
		}

		var link float64
		switch v := pdu.Value.(type) {
		case string:
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "yes", "up", "true", "1":
				link = 1
			default:
				link = 0
			}
		case []byte:
			switch strings.ToLower(strings.TrimSpace(string(v))) {
			case "yes", "up", "true", "1":
				link = 1
			default:
				link = 0
			}
		default:
			f, ok := snmpPDUToFloat64(pdu)
			if ok && f != 0 {
				link = 1
			} else {
				link = 0
			}
		}

		linkByIdx[idx] = link
		return nil
	}); err != nil {
		return nil, err
	}

	if err := snmp.BulkWalk(ifTxOID, func(pdu gosnmp.SnmpPDU) error {
		idx := strings.TrimPrefix(pdu.Name, ifTxOID+".")
		if idx == pdu.Name {
			idx = strings.TrimPrefix(pdu.Name, ifTxOID)
			idx = strings.TrimPrefix(idx, ".")
		}
		if idx == "" {
			return nil
		}
		f, ok := snmpPDUToFloat64(pdu)
		if ok {
			txBytesByIdx[idx] = f
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := snmp.BulkWalk(ifRxOID, func(pdu gosnmp.SnmpPDU) error {
		idx := strings.TrimPrefix(pdu.Name, ifRxOID+".")
		if idx == pdu.Name {
			idx = strings.TrimPrefix(pdu.Name, ifRxOID)
			idx = strings.TrimPrefix(idx, ".")
		}
		if idx == "" {
			return nil
		}
		f, ok := snmpPDUToFloat64(pdu)
		if ok {
			rxBytesByIdx[idx] = f
		}
		return nil
	}); err != nil {
		return nil, err
	}

	metrics := []core.Metric{}
	for idx, ifName := range ifNameByIdx {
		if strings.TrimSpace(ifName) == "" {
			continue
		}

		labels := map[string]string{
			"if_name":     ifName,
			"description": "",
			"zone":        "",
			"mac":         "",
			"ip_addr":     "",
		}

		if link, ok := linkByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_link_state",
				Value:  link,
				Labels: labels,
			})
		}
		if tx, ok := txBytesByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_out_bytes_total",
				Value:  tx,
				Labels: labels,
			})
		}
		if rx, ok := rxBytesByIdx[idx]; ok {
			metrics = append(metrics, core.Metric{
				Name:   "netsec_interface_traffic_in_bytes_total",
				Value:  rx,
				Labels: labels,
			})
		}
	}

	return metrics, nil
}
