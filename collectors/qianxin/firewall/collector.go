package firewall

import (
	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func Collect(c *client.Client, dev core.Device) ([]core.Metric, error) {
	systemMetrics, err := CollectSystemMetrics(c, dev)
	if err != nil {
		systemMetrics = nil
	}

	sessionMetrics, err := CollectSessionMetrics(c, dev)
	if err != nil {
		sessionMetrics = nil
	}

	interfaceMetrics, err := CollectInterfaceMetrics(c, dev)
	if err != nil {
		interfaceMetrics = nil
	}

	haMetrics, err := CollectHAMetrics(c, dev)
	if err != nil {
		haMetrics = nil
	}

	userMetrics, err := CollectUserMetrics(c, dev)
	if err != nil {
		userMetrics = nil
	}

	logMetrics, err := CollectLogMetrics(c, dev)
	if err != nil {
		logMetrics = nil
	}

	policyMetrics, err := CollectPolicyMetrics(c, dev)
	if err != nil {
		policyMetrics = nil
	}

	vpnMetrics, err := CollectVPNMetrics(c, dev)
	if err != nil {
		vpnMetrics = nil
	}

	healthMetrics, err := CollectHealthMetrics(c, dev)
	if err != nil {
		healthMetrics = nil
	}

	metrics := append([]core.Metric{}, systemMetrics...)
	metrics = append(metrics, sessionMetrics...)
	metrics = append(metrics, interfaceMetrics...)
	metrics = append(metrics, haMetrics...)
	metrics = append(metrics, userMetrics...)
	metrics = append(metrics, logMetrics...)
	metrics = append(metrics, policyMetrics...)
	metrics = append(metrics, vpnMetrics...)
	metrics = append(metrics, healthMetrics...)
	return metrics, nil
}
