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

	interfaceLabelNames = []string{"device", "host", "interface", "description", "zone", "mac", "ipaddress", "vendor", "type"}

	interfacePhysicalStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_physical_status",
			Help: "Network security device interface physical status (1=true, 0=false)",
		},
		interfaceLabelNames,
	)
	interfaceLinkStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_link_status",
			Help: "Network security device interface link status (1=true, 0=false)",
		},
		interfaceLabelNames,
	)
	interfaceMTU = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_mtu",
			Help: "Network security device interface MTU",
		},
		interfaceLabelNames,
	)
	interfacePing = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_ping",
			Help: "Network security device interface ping enabled (1=true, 0=false)",
		},
		interfaceLabelNames,
	)
	interfaceWanEnable = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_wan_enable",
			Help: "Network security device interface WAN enabled (ENABLE=1, DISABLE=0)",
		},
		interfaceLabelNames,
	)
	interfaceEthToolType = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_eth_tool_type",
			Help: "Network security device interface port type (TP=0, FIBER=1)",
		},
		interfaceLabelNames,
	)
	interfaceIfTypePhysical = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_if_type_physical",
			Help: "Network security device interface is physical (PHYSICALIF=1, else=0)",
		},
		interfaceLabelNames,
	)
	interfaceIfMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_if_mode",
			Help: "Network security device interface mode (BRIDGE=0, ROUTE=1)",
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
			Name: "netsec_interface_send_speed_bits",
			Help: "Network security device interface send throughput (bits per second)",
		},
		interfaceLabelNames,
	)
	interfaceRecvSpeedBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_recv_speed_bits",
			Help: "Network security device interface receive throughput (bits per second)",
		},
		interfaceLabelNames,
	)
	interfaceSendPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_send_packets",
			Help: "Network security device interface send packets",
		},
		interfaceLabelNames,
	)
	interfaceRecvPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_interface_recv_packets",
			Help: "Network security device interface receive packets",
		},
		interfaceLabelNames,
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
	case "netsec_interface_physical_status":
		interfacePhysicalStatus.With(m.Labels).Set(m.Value)
	case "netsec_interface_link_status":
		interfaceLinkStatus.With(m.Labels).Set(m.Value)
	case "netsec_interface_mtu":
		interfaceMTU.With(m.Labels).Set(m.Value)
	case "netsec_interface_ping":
		interfacePing.With(m.Labels).Set(m.Value)
	case "netsec_interface_wan_enable":
		interfaceWanEnable.With(m.Labels).Set(m.Value)
	case "netsec_interface_eth_tool_type":
		interfaceEthToolType.With(m.Labels).Set(m.Value)
	case "netsec_interface_if_type_physical":
		interfaceIfTypePhysical.With(m.Labels).Set(m.Value)
	case "netsec_interface_if_mode":
		interfaceIfMode.With(m.Labels).Set(m.Value)
	case "netsec_interface_speed_mbps":
		interfaceSpeedMbps.With(m.Labels).Set(m.Value)
	case "netsec_interface_send_speed_bits":
		interfaceSendSpeedBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_recv_speed_bits":
		interfaceRecvSpeedBits.With(m.Labels).Set(m.Value)
	case "netsec_interface_send_packets":
		interfaceSendPackets.With(m.Labels).Set(m.Value)
	case "netsec_interface_recv_packets":
		interfaceRecvPackets.With(m.Labels).Set(m.Value)
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
