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
		[]string{"device_name", "instance", "name", "interface", "destination", "vendor", "role"},
	)

	cpuUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_system_cpu_usage_percent",
			Help: "Network security device CPU usage percent",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	memoryUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_system_memory_usage_percent",
			Help: "Network security device memory usage percent",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	diskUsagePercent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_system_disk_usage_percent",
			Help: "Network security device disk usage percent",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	activeSessionsCurrent = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_session_active_current",
			Help: "Network security device active sessions (current)",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	newSessionsPerSecond = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_sessions_new_per_second",
			Help: "Network security device new sessions per second (REAL-TIME)",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	sessionMaxLimit = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_session_max_limit",
			Help: "Network security device maximum session limit",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	interfaceSendBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_send_bits",
			Help: "Network security device interface total realtime send throughput (bits)",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	interfaceRecvBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_recv_bits",
			Help: "Network security device interface total realtime receive throughput (bits)",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	interfaceLabelNames = []string{"device_name", "instance", "if_name", "description", "zone", "mac", "ip_addr", "vendor", "role"}

	interfacePhysicalStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_physical_state",
			Help: "Network security device interface physical state (1=true, 0=false)",
		},
		interfaceLabelNames,
	)
	interfaceLinkStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_link_state",
			Help: "Network security device interface link state (1=true, 0=false)",
		},
		interfaceLabelNames,
	)
	interfaceMTU = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_mtu_bytes",
			Help: "Network security device interface MTU (bytes)",
		},
		interfaceLabelNames,
	)
	interfacePing = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_ping_up",
			Help: "Network security device interface ping up (1=true, 0=false)",
		},
		interfaceLabelNames,
	)
	interfaceWanEnable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_role",
			Help: "Network security device interface role (WAN=1, NON-WAN=0)",
		},
		interfaceLabelNames,
	)
	interfaceEthToolType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_media_type",
			Help: "Network security device interface media type (TP=0, FIBER=1)",
		},
		interfaceLabelNames,
	)
	interfaceIfTypePhysical = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_category",
			Help: "Network security device interface category (PHYSICALIF=1, else=0)",
		},
		interfaceLabelNames,
	)
	interfaceIfMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_layer_mode",
			Help: "Network security device interface layer mode (BRIDGE=0, ROUTE=1)",
		},
		interfaceLabelNames,
	)
	interfaceSpeedMbps = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_speed_mbps",
			Help: "Network security device interface negotiated speed (Mbps)",
		},
		interfaceLabelNames,
	)
	interfaceSendSpeedBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_traffic_out_bps",
			Help: "Network security device interface traffic out (bps)",
		},
		interfaceLabelNames,
	)
	interfaceRecvSpeedBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_traffic_in_bps",
			Help: "Network security device interface traffic in (bps)",
		},
		interfaceLabelNames,
	)
	interfaceSendPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_traffic_out_packets_total",
			Help: "Network security device interface traffic out packets total",
		},
		interfaceLabelNames,
	)
	interfaceRecvPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_traffic_in_packets_total",
			Help: "Network security device interface traffic in packets total",
		},
		interfaceLabelNames,
	)
	interfaceSendBytesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_traffic_out_bytes_total",
			Help: "Network security device interface traffic out bytes total",
		},
		interfaceLabelNames,
	)
	interfaceRecvBytesTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_traffic_in_bytes_total",
			Help: "Network security device interface traffic in bytes total",
		},
		interfaceLabelNames,
	)

	haEnabled = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_ha_enabled",
			Help: "Network security device HA enabled (1 enabled, 0 disabled)",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	haMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_ha_mode",
			Help: "Network security device HA mode (ACTIVE-ACTIVE=1, ACTIVE-PASSIVE=2, MIRROR=3)",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	deviceUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_device_up",
			Help: "Network security device status",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)

	scrapeDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_scrape_duration_seconds",
			Help: "Network security device scrape duration",
		},
		[]string{"device_name", "instance", "vendor", "role"},
	)
)

func InitMetrics() {
	prometheus.MustRegister(iplinkStatus)
	prometheus.MustRegister(cpuUsagePercent)
	prometheus.MustRegister(memoryUsagePercent)
	prometheus.MustRegister(diskUsagePercent)
	prometheus.MustRegister(activeSessionsCurrent)
	prometheus.MustRegister(newSessionsPerSecond)
	prometheus.MustRegister(sessionMaxLimit)
	prometheus.MustRegister(interfaceSendBits)
	prometheus.MustRegister(interfaceRecvBits)
	prometheus.MustRegister(interfacePhysicalStatus)
	prometheus.MustRegister(interfaceLinkStatus)
	prometheus.MustRegister(interfaceMTU)
	prometheus.MustRegister(interfacePing)
	prometheus.MustRegister(interfaceWanEnable)
	prometheus.MustRegister(interfaceEthToolType)
	prometheus.MustRegister(interfaceIfTypePhysical)
	prometheus.MustRegister(interfaceIfMode)
	prometheus.MustRegister(interfaceSpeedMbps)
	prometheus.MustRegister(interfaceSendSpeedBits)
	prometheus.MustRegister(interfaceRecvSpeedBits)
	prometheus.MustRegister(interfaceSendPackets)
	prometheus.MustRegister(interfaceRecvPackets)
	prometheus.MustRegister(interfaceSendBytesTotal)
	prometheus.MustRegister(interfaceRecvBytesTotal)
	prometheus.MustRegister(haEnabled)
	prometheus.MustRegister(haMode)
	prometheus.MustRegister(deviceUp)
	prometheus.MustRegister(scrapeDuration)
}

func SetMetric(m Metric) {
	switch m.Name {
	case "netsec_iplink_status":
		iplinkStatus.With(m.Labels).Set(m.Value)
	case "netsec_system_cpu_usage_percent":
		cpuUsagePercent.With(m.Labels).Set(m.Value)
	case "netsec_system_memory_usage_percent":
		memoryUsagePercent.With(m.Labels).Set(m.Value)
	case "netsec_system_disk_usage_percent":
		diskUsagePercent.With(m.Labels).Set(m.Value)
	case "netsec_session_active_current":
		activeSessionsCurrent.With(m.Labels).Set(m.Value)
	case "netsec_sessions_new_per_second":
		newSessionsPerSecond.With(m.Labels).Set(m.Value)
	case "netsec_session_max_limit":
		sessionMaxLimit.With(m.Labels).Set(m.Value)
	case "netsec_interface_send_bits":
		interfaceSendBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_recv_bits":
		interfaceRecvBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_physical_state":
		interfacePhysicalStatus.With(m.Labels).Set(m.Value)
	case "netsec_interface_link_state":
		interfaceLinkStatus.With(m.Labels).Set(m.Value)
	case "netsec_interface_mtu_bytes":
		interfaceMTU.With(m.Labels).Set(m.Value)
	case "netsec_interface_ping_up":
		interfacePing.With(m.Labels).Set(m.Value)
	case "netsec_interface_role":
		interfaceWanEnable.With(m.Labels).Set(m.Value)
	case "netsec_interface_media_type":
		interfaceEthToolType.With(m.Labels).Set(m.Value)
	case "netsec_interface_category":
		interfaceIfTypePhysical.With(m.Labels).Set(m.Value)
	case "netsec_interface_layer_mode":
		interfaceIfMode.With(m.Labels).Set(m.Value)
	case "netsec_interface_speed_mbps":
		interfaceSpeedMbps.With(m.Labels).Set(m.Value)
	case "netsec_interface_traffic_out_bps":
		interfaceSendSpeedBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_traffic_in_bps":
		interfaceRecvSpeedBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_traffic_out_packets_total":
		interfaceSendPackets.With(m.Labels).Set(m.Value)
	case "netsec_interface_traffic_in_packets_total":
		interfaceRecvPackets.With(m.Labels).Set(m.Value)
	case "netsec_interface_traffic_out_bytes_total":
		interfaceSendBytesTotal.With(m.Labels).Set(m.Value)
	case "netsec_interface_traffic_in_bytes_total":
		interfaceRecvBytesTotal.With(m.Labels).Set(m.Value)
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
