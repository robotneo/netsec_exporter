package core

import (
	"log"
	"time"
)

func Scheduler(devices []Device, jobs chan<- Job, interval int) {

	if interval <= 0 {
		log.Printf("invalid interval=%d, fallback to 60", interval)
		interval = 60
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)

	for {

		log.Println("start collect cycle")

		for _, d := range devices {
			jobs <- Job{Device: d}
		}

		<-ticker.C
	}
}
