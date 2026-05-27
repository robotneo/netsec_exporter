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
		[]string{"device", "name", "interface", "destination", "vendor", "type"},
	)

	deviceUp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_device_up",
			Help: "Network security device status",
		},
		[]string{"device", "vendor", "type"},
	)

	scrapeDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "netsec_scrape_duration_seconds",
			Help: "Network security device scrape duration",
		},
		[]string{"device", "vendor", "type"},
	)
)

func InitMetrics() {
	prometheus.MustRegister(iplinkStatus)
	prometheus.MustRegister(deviceUp)
	prometheus.MustRegister(scrapeDuration)
}

func SetMetric(m Metric) {
	switch m.Name {
	case "netsec_iplink_status":
		iplinkStatus.With(m.Labels).Set(m.Value)
	case "netsec_device_up":
		deviceUp.With(m.Labels).Set(m.Value)
	case "netsec_scrape_duration_seconds":
		scrapeDuration.With(m.Labels).Set(m.Value)
	}
}
