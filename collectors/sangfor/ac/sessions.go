package ac

import (
	"context"
	"strings"
	"time"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"

	"github.com/gosnmp/gosnmp"
)

// CollectSessionMetrics 用于承载 AC 的会话相关指标。
func CollectSessionMetrics(c *client.ACClient, dev core.Device) ([]core.Metric, error) {
	sessionNum := 0.0
	currentOnlineUsers := -1.0
	maxOnlineUsers := -1.0
	maxSessions := -1.0

	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    int64  `json:"data"`
	}

	err := c.DoJSON(context.Background(), "/v1/status/session-num", &resp)
	if err == nil && resp.Code == 0 {
		sessionNum = float64(resp.Data)
	}

	err = c.DoJSON(context.Background(), "/v1/status/online-user", &resp)
	if err == nil && resp.Code == 0 {
		currentOnlineUsers = float64(resp.Data)
	}

	if strings.TrimSpace(dev.SNMPCommunity) != "" {
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

		if err := snmp.Connect(); err == nil {
			result, err := snmp.Get([]string{
				".1.3.6.1.4.1.35047.2.1.1.2.0",
				".1.3.6.1.4.1.35047.2.1.1.5.0",
			})
			if err == nil {
				for _, pdu := range result.Variables {
					v, ok := snmpPDUToFloat64(pdu)
					if !ok {
						continue
					}
					switch pdu.Name {
					case ".1.3.6.1.4.1.35047.2.1.1.2.0":
						maxOnlineUsers = v
					case ".1.3.6.1.4.1.35047.2.1.1.5.0":
						maxSessions = v
					}
				}
			}
			_ = snmp.Conn.Close()
		}
	}

	metrics := []core.Metric{
		{
			Name:   "netsec_session_active_current",
			Value:  sessionNum,
			Labels: nil,
		},
	}

	if currentOnlineUsers >= 0 {
		metrics = append(metrics, core.Metric{
			Name:   "netsec_online_users_current",
			Value:  currentOnlineUsers,
			Labels: nil,
		})
	}
	if maxOnlineUsers >= 0 {
		metrics = append(metrics, core.Metric{
			Name:   "netsec_online_users_max_limit",
			Value:  maxOnlineUsers,
			Labels: nil,
		})
	}
	if maxSessions >= 0 {
		metrics = append(metrics, core.Metric{
			Name:   "netsec_session_max_limit",
			Value:  maxSessions,
			Labels: nil,
		})
	}

	return metrics, nil
}
