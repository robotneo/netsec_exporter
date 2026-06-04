package core

import (
	"log"
	"time"
)

func Worker(jobs <-chan Job) {

	for job := range jobs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("device %s: recovered from panic: %v", job.Device.Name, r)
				}
			}()

			start := time.Now()

			c, ok := GetCollector(job.Device.Vendor)
			if !ok {
				log.Printf("device %s: no collector for vendor %s", job.Device.Name, job.Device.Vendor)
				return
			}

			metrics, err := c.Collect(job.Device)
			duration := time.Since(start).Seconds()

			SetMetric(Metric{
				Name:  "netsec_scrape_duration_seconds",
				Value: duration,
				Labels: map[string]string{
					"device_name": job.Device.Name,
					"instance":    job.Device.Host,
					"vendor": job.Device.Vendor,
					"type":   job.Device.Type,
				},
			})

			if err != nil {
				log.Printf("device %s: scrape failed: %v", job.Device.Name, err)
				SetMetric(Metric{
					Name:  "netsec_device_up",
					Value: 0,
					Labels: map[string]string{
						"device_name": job.Device.Name,
						"instance":    job.Device.Host,
						"vendor": job.Device.Vendor,
						"type":   job.Device.Type,
					},
				})
				return
			}

			log.Printf("device %s: scrape success, metrics: %d", job.Device.Name, len(metrics))
			SetMetric(Metric{
				Name:  "netsec_device_up",
				Value: 1,
				Labels: map[string]string{
					"device_name": job.Device.Name,
					"instance":    job.Device.Host,
					"vendor": job.Device.Vendor,
					"type":   job.Device.Type,
				},
			})

			for _, m := range metrics {
				if m.Labels == nil {
					m.Labels = make(map[string]string)
				}
				m.Labels = NormalizeCommonLabels(m.Labels)
				if _, ok := m.Labels["device_name"]; !ok {
					m.Labels["device_name"] = job.Device.Name
				}
				if _, ok := m.Labels["instance"]; !ok {
					m.Labels["instance"] = job.Device.Host
				}
				if _, ok := m.Labels["vendor"]; !ok {
					m.Labels["vendor"] = job.Device.Vendor
				}
				if _, ok := m.Labels["type"]; !ok {
					m.Labels["type"] = job.Device.Type
				}
				SetMetric(m)
			}
		}()
	}
}
