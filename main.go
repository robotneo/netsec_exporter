package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"netsec_exporter/collectors"
	"netsec_exporter/core"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Global struct {
		Interval           int  `yaml:"interval"`
		Timeout            int  `yaml:"timeout"`
		Workers            int  `yaml:"workers"`
		InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	} `yaml:"global"`

	Metrics struct {
		Listen string `yaml:"listen"`
	} `yaml:"metrics"`

	Devices []core.Device `yaml:"devices"`
}

var config Config

func load() {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatalf("read config failed: %v", err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("unmarshal config failed: %v", err)
	}
}

func installService() {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("get executable path failed: %v", err)
	}
	absExePath, _ := filepath.Abs(exePath)
	workingDir := filepath.Dir(absExePath)

	serviceContent := fmt.Sprintf(`[Unit]
Description=Network Security Device Exporter
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, workingDir, absExePath)

	serviceFile := "/etc/systemd/system/netsec_exporter.service"
	err = os.WriteFile(serviceFile, []byte(serviceContent), 0644)
	if err != nil {
		log.Fatalf("Failed to write service file: %v. Please run with sudo.", err)
	}

	fmt.Printf("Successfully created service file: %s\n", serviceFile)
	fmt.Println("You can now manage the service using:")
	fmt.Println("  systemctl daemon-reload")
	fmt.Println("  systemctl enable netsec_exporter")
	fmt.Println("  systemctl start netsec_exporter")
	fmt.Println("  systemctl status netsec_exporter")
}

func main() {
	install := flag.Bool("install", false, "Install systemd service")
	flag.Parse()

	if *install {
		installService()
		return
	}

	load()

	core.InitMetrics()

	// register plugins
	core.Register(&collectors.DBAPP{})
	// core.Register(&collectors.H3C{})    // 暂不纳入采集，仅作示例
	// core.Register(&collectors.Huawei{}) // 暂不纳入采集，仅作示例

	jobs := make(chan core.Job, 200)

	// worker pool
	for i := 0; i < config.Global.Workers; i++ {
		go core.Worker(jobs)
	}

	// scheduler
	go core.Scheduler(config.Devices, jobs, config.Global.Interval)

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	log.Printf("Starting netsec_exporter, listen on %s", config.Metrics.Listen)
	if err := r.Run(config.Metrics.Listen); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
