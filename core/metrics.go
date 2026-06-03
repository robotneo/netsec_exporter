package core

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	iplinkStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_iplink_status",
			Help: "Network security device IP link status",
		},
		[]string{"device", "host", "name", "interface", "destination", "vendor", "type"},
	)

	cpuUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_cpu_usage_percent",
			Help: "Network security device CPU usage percent",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	memoryUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_memory_usage_percent",
			Help: "Network security device memory usage percent",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	diskUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_disk_usage_percent",
			Help: "Network security device disk usage percent",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	concurrentSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_session_concurrent",
			Help: "Network security device concurrent sessions",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	newSessions = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_session_creation_rate",
			Help: "Network security device session creation rate (REAL-TIME)",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	interfaceSendBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_send_bits",
			Help: "Network security device interface total realtime send throughput (bits)",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	interfaceRecvBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_recv_bits",
			Help: "Network security device interface total realtime receive throughput (bits)",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	haEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_ha_enabled",
			Help: "Network security device HA enabled (1 enabled, 0 disabled)",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	haMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_ha_mode",
			Help: "Network security device HA mode (ACTIVE-ACTIVE=1, ACTIVE-PASSIVE=2, MIRROR=3)",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	deviceUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_device_up",
			Help: "Network security device status",
		},
		[]string{"device", "host", "vendor", "type"},
	)

	scrapeDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_scrape_duration_seconds",
			Help: "Network security device scrape duration",
		},
		[]string{"device", "host", "vendor", "type"},
	)
)

func InitMetrics() {
	prometheus.MustRegister(iplinkStatus)
	prometheus.MustRegister(cpuUsagePercent)
	prometheus.MustRegister(memoryUsagePercent)
	prometheus.MustRegister(diskUsagePercent)
	prometheus.MustRegister(concurrentSessions)
	prometheus.MustRegister(newSessions)
	prometheus.MustRegister(interfaceSendBits)
	prometheus.MustRegister(interfaceRecvBits)
	prometheus.MustRegister(haEnabled)
	prometheus.MustRegister(haMode)
	prometheus.MustRegister(deviceUp)
	prometheus.MustRegister(scrapeDuration)
}

func SetMetric(m Metric) {
	switch m.Name {
	case "netsec_iplink_status":
		iplinkStatus.With(m.Labels).Set(m.Value)
	case "netsec_cpu_usage_percent":
		cpuUsagePercent.With(m.Labels).Set(m.Value)
	case "netsec_memory_usage_percent":
		memoryUsagePercent.With(m.Labels).Set(m.Value)
	case "netsec_disk_usage_percent":
		diskUsagePercent.With(m.Labels).Set(m.Value)
	case "netsec_session_concurrent":
		concurrentSessions.With(m.Labels).Set(m.Value)
	case "netsec_session_creation_rate":
		newSessions.With(m.Labels).Set(m.Value)
	case "netsec_interface_send_bits":
		interfaceSendBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_recv_bits":
		interfaceRecvBits.With(m.Labels).Set(m.Value)
	case "netsec_ha_enabled":
		haEnabled.With(m.Labels).Set(m.Value)
	case "netsec_ha_mode":
		haMode.With(m.Labels).Set(m.Value)
	case "netsec_device_up":
		deviceUp.With(m.Labels).Set(m.Value)
	case "netsec_scrape_duration_seconds":
		scrapeDuration.With(m.Labels).Set(m.Value)
	}
}
