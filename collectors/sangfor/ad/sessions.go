package ad

import (
	"fmt"
	"strings"
	"time"

	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

func CollectSessionMetrics(dev core.Device) ([]core.Metric, error) {
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

		adConnsOID      = ".1.3.6.1.4.1.35047.2.2.1.0"
		adVsConnsOID    = ".1.3.6.1.4.1.35047.2.2.3.0"
		adVsNewConnsOID = ".1.3.6.1.4.1.35047.2.2.4.0"
		adVsNumberOID   = ".1.3.6.1.4.1.35047.2.2.22.0"
		adPoolNumberOID = ".1.3.6.1.4.1.35047.2.2.23.0"
		adNodeNumberOID = ".1.3.6.1.4.1.35047.2.2.24.0"
	)

	result, err := snmp.Get([]string{
		sysNameOID,
		adConnsOID,
		adVsConnsOID,
		adVsNewConnsOID,
		adVsNumberOID,
		adPoolNumberOID,
		adNodeNumberOID,
	})
	if err != nil {
		return nil, err
	}

	sysName := ""
	conns := 0.0
	newConns := 0.0
	vsConns := 0.0
	vsNewConns := 0.0
	vsNum := 0.0
	poolNum := 0.0
	nodeNum := 0.0

	for _, pdu := range result.Variables {
		switch pdu.Name {
		case sysNameOID:
			switch v := pdu.Value.(type) {
			case string:
				sysName = strings.TrimSpace(v)
			case []byte:
				sysName = strings.TrimSpace(string(v))
			}
		case adConnsOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				conns = v
			}
		case adVsConnsOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				vsConns = v
			}
		case adVsNewConnsOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				vsNewConns = v
			}
		case adVsNumberOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				vsNum = v
			}
		case adPoolNumberOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				poolNum = v
			}
		case adNodeNumberOID:
			if v, ok := snmpPDUToFloat64(pdu); ok {
				nodeNum = v
			}
		}
	}

	newConns = conns

	labels := map[string]string{}
	if sysName != "" {
		labels["device_name"] = sysName
	}

	return []core.Metric{
		{Name: "netsec_session_active_current", Value: conns, Labels: labels},
		{Name: "netsec_sessions_new_per_second", Value: newConns, Labels: labels},
		{Name: "netsec_vs_session_active_current", Value: vsConns, Labels: labels},
		{Name: "netsec_vs_sessions_new_per_second", Value: vsNewConns, Labels: labels},
		{Name: "netsec_vs_total", Value: vsNum, Labels: labels},
		{Name: "netsec_pool_total", Value: poolNum, Labels: labels},
		{Name: "netsec_node_total", Value: nodeNum, Labels: labels},
	}, nil
}
