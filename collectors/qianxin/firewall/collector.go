package firewall

import (
	"errors"
	"strings"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func Collect(c *client.Client, dev core.Device) ([]core.Metric, error) {
	var sess client.Session
	if strings.TrimSpace(dev.Token) != "" {
		sess = client.NewTokenSession(dev.Username, dev.Token)
	} else {
		s, err := c.Login(dev)
		if err != nil {
			return nil, err
		}
		sess = s
	}

	collectWithRelogin := func(fn func(client.Session) ([]core.Metric, error)) ([]core.Metric, error) {
		ms, err := fn(sess)
		if err == nil {
			return ms, nil
		}
		if !errors.Is(err, client.ErrAuthExpired) {
			return nil, err
		}
		s, loginErr := c.Login(dev)
		if loginErr != nil {
			return nil, err
		}
		sess = s
		return fn(sess)
	}

	systemMetrics, err := collectWithRelogin(func(s client.Session) ([]core.Metric, error) {
		return CollectSystemMetrics(c, s, dev)
	})
	if err != nil {
		systemMetrics = nil
	}

	sessionMetrics, err := collectWithRelogin(func(s client.Session) ([]core.Metric, error) {
		return CollectSessionMetrics(c, s, dev)
	})
	if err != nil {
		sessionMetrics = nil
	}

	interfaceMetrics, err := collectWithRelogin(func(s client.Session) ([]core.Metric, error) {
		return CollectInterfaceMetrics(c, s, dev)
	})
	if err != nil {
		interfaceMetrics = nil
	}

	haMetrics, err := collectWithRelogin(func(s client.Session) ([]core.Metric, error) {
		return CollectHAMetrics(c, s, dev)
	})
	if err != nil {
		haMetrics = nil
	}

	healthMetrics, err := collectWithRelogin(func(s client.Session) ([]core.Metric, error) {
		return CollectHealthMetrics(c, s, dev)
	})
	if err != nil {
		healthMetrics = nil
	}

	metrics := append([]core.Metric{}, systemMetrics...)
	metrics = append(metrics, sessionMetrics...)
	metrics = append(metrics, interfaceMetrics...)
	metrics = append(metrics, haMetrics...)
	metrics = append(metrics, healthMetrics...)
	applyHostnameLabel(metrics, detectHostname(metrics))
	return metrics, nil
}

func detectHostname(metrics []core.Metric) string {
	for _, m := range metrics {
		if m.Labels == nil {
			continue
		}
		if hostname := strings.TrimSpace(m.Labels["hostname"]); hostname != "" {
			return hostname
		}
	}
	return ""
}
