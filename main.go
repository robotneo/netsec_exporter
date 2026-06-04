package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netsec_exporter/collectors"
	"netsec_exporter/core"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
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

	AuthFile string `yaml:"auth_file"`
}

var config Config

type authEntry struct {
	Vendor   string `yaml:"vendor"`
	Type     string `yaml:"type"`
	Token    string `yaml:"token"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type authFile struct {
	Auths map[string]authEntry `yaml:"auths"`
}

func load(configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("read config failed from %s: %v", configPath, err)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("unmarshal config failed: %v", err)
	}
}

func normalizeConfig(configPath string) {
	if config.Global.Interval <= 0 {
		log.Printf("invalid global.interval=%d in %s, fallback to 60", config.Global.Interval, configPath)
		config.Global.Interval = 60
	}
	if config.Global.Timeout <= 0 {
		log.Printf("invalid global.timeout=%d in %s, fallback to 10", config.Global.Timeout, configPath)
		config.Global.Timeout = 10
	}
	if config.Global.Workers <= 0 {
		log.Printf("invalid global.workers=%d in %s, fallback to 1", config.Global.Workers, configPath)
		config.Global.Workers = 1
	}
	if config.Metrics.Listen == "" {
		log.Printf("empty metrics.listen in %s, fallback to :9808", configPath)
		config.Metrics.Listen = ":9808"
	}
}

func loadAuths(authPath string) (map[string]authEntry, error) {
	if strings.TrimSpace(authPath) == "" {
		return map[string]authEntry{}, nil
	}
	data, err := os.ReadFile(authPath)
	if err != nil {
		return nil, err
	}
	var af authFile
	if err := yaml.Unmarshal(data, &af); err != nil {
		return nil, err
	}
	if af.Auths == nil {
		af.Auths = map[string]authEntry{}
	}
	return af.Auths, nil
}

var metricHelp = map[string]string{
	"netsec_iplink_status":                 "Network security device IP link status",
	"netsec_cpu_usage_percent":             "Network security device CPU usage percent",
	"netsec_memory_usage_percent":          "Network security device memory usage percent",
	"netsec_disk_usage_percent":            "Network security device disk usage percent",
	"netsec_session_concurrent":            "Network security device concurrent sessions",
	"netsec_session_creation_rate":         "Network security device session creation rate (REAL-TIME)",
	"netsec_interface_send_bits":           "Network security device interface total realtime send throughput (bits)",
	"netsec_interface_recv_bits":           "Network security device interface total realtime receive throughput (bits)",
	"netsec_interface_physical_status":     "Network security device interface physical status (1=true, 0=false)",
	"netsec_interface_link_status":         "Network security device interface link status (1=true, 0=false)",
	"netsec_interface_mtu":                 "Network security device interface MTU",
	"netsec_interface_ping":                "Network security device interface ping enabled (1=true, 0=false)",
	"netsec_interface_wan_enable":          "Network security device interface WAN enabled (ENABLE=1, DISABLE=0)",
	"netsec_interface_eth_tool_type":       "Network security device interface port type (TP=0, FIBER=1)",
	"netsec_interface_if_type_physical":    "Network security device interface is physical (PHYSICALIF=1, else=0)",
	"netsec_interface_if_mode":             "Network security device interface mode (BRIDGE=0, ROUTE=1)",
	"netsec_interface_speed_mbps":          "Network security device interface negotiated speed (Mbps)",
	"netsec_interface_send_speed_bits":     "Network security device interface send throughput (bits per second)",
	"netsec_interface_recv_speed_bits":     "Network security device interface receive throughput (bits per second)",
	"netsec_interface_send_packets":        "Network security device interface send packets",
	"netsec_interface_recv_packets":        "Network security device interface receive packets",
	"netsec_ha_enabled":                    "Network security device HA enabled (1 enabled, 0 disabled)",
	"netsec_ha_mode":                       "Network security device HA mode (ACTIVE-ACTIVE=1, ACTIVE-PASSIVE=2, MIRROR=3)",
	"netsec_device_up":                     "Network security device status",
	"netsec_scrape_duration_seconds":       "Network security device scrape duration",
	"netsec_probe_scrape_duration_seconds": "Network security device probe scrape duration",
}

func getMetricHelp(name string) string {
	if v, ok := metricHelp[name]; ok {
		return v
	}
	return "Network security device metric"
}

type probeCollector struct {
	device core.Device
}

func (c *probeCollector) Describe(ch chan<- *prometheus.Desc) {}

func (c *probeCollector) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()

	defer func() {
		_ = recover()
	}()

	col, ok := core.GetCollector(c.device.Vendor)
	if !ok {
		c.emitProbeResult(ch, start, errors.New("no collector for vendor"))
		return
	}

	metrics, err := col.Collect(c.device)
	c.emitProbeMetrics(ch, start, metrics, err)
}

func (c *probeCollector) emitProbeResult(ch chan<- prometheus.Metric, start time.Time, err error) {
	duration := time.Since(start).Seconds()

	labels := map[string]string{
		"device": c.device.Name,
		"host":   c.device.Host,
		"vendor": c.device.Vendor,
		"type":   c.device.Type,
	}

	up := 1.0
	if err != nil {
		up = 0
	}

	c.emitGauge(ch, "netsec_device_up", labels, up)
	c.emitGauge(ch, "netsec_scrape_duration_seconds", labels, duration)
}

func (c *probeCollector) emitProbeMetrics(ch chan<- prometheus.Metric, start time.Time, metrics []core.Metric, scrapeErr error) {
	duration := time.Since(start).Seconds()

	baseLabels := map[string]string{
		"device": c.device.Name,
		"host":   c.device.Host,
		"vendor": c.device.Vendor,
		"type":   c.device.Type,
	}

	up := 1.0
	if scrapeErr != nil {
		up = 0
	}

	all := append([]core.Metric{}, metrics...)
	all = append(all,
		core.Metric{Name: "netsec_device_up", Value: up, Labels: baseLabels},
		core.Metric{Name: "netsec_scrape_duration_seconds", Value: duration, Labels: baseLabels},
	)

	for i := range all {
		if all[i].Labels == nil {
			all[i].Labels = map[string]string{}
		}
		if _, ok := all[i].Labels["device"]; !ok {
			all[i].Labels["device"] = c.device.Name
		}
		if _, ok := all[i].Labels["host"]; !ok {
			all[i].Labels["host"] = c.device.Host
		}
		if _, ok := all[i].Labels["vendor"]; !ok {
			all[i].Labels["vendor"] = c.device.Vendor
		}
		if _, ok := all[i].Labels["type"]; !ok {
			all[i].Labels["type"] = c.device.Type
		}
	}

	byName := map[string][]core.Metric{}
	for _, m := range all {
		byName[m.Name] = append(byName[m.Name], m)
	}

	for name, ms := range byName {
		labelSet := map[string]struct{}{}
		for _, m := range ms {
			for k := range m.Labels {
				labelSet[k] = struct{}{}
			}
		}
		var labelNames []string
		for k := range labelSet {
			labelNames = append(labelNames, k)
		}
		sort.Strings(labelNames)

		desc := prometheus.NewDesc(name, getMetricHelp(name), labelNames, nil)

		for _, m := range ms {
			labelValues := make([]string, 0, len(labelNames))
			for _, ln := range labelNames {
				labelValues = append(labelValues, m.Labels[ln])
			}
			ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, m.Value, labelValues...)
		}
	}
}

func (c *probeCollector) emitGauge(ch chan<- prometheus.Metric, name string, labels map[string]string, value float64) {
	labelNames := make([]string, 0, len(labels))
	for k := range labels {
		labelNames = append(labelNames, k)
	}
	sort.Strings(labelNames)
	labelValues := make([]string, 0, len(labelNames))
	for _, ln := range labelNames {
		labelValues = append(labelValues, labels[ln])
	}
	desc := prometheus.NewDesc(name, getMetricHelp(name), labelNames, nil)
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, labelValues...)
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
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	if *install {
		installService()
		return
	}

	load(*configPath)
	normalizeConfig(*configPath)

	core.InitMetrics()

	auths, err := loadAuths(config.AuthFile)
	if err != nil {
		log.Fatalf("load auth_file failed from %s: %v", config.AuthFile, err)
	}

	// register plugins
	core.Register(&collectors.DBAPP{})
	core.Register(&collectors.Sangfor{})
	// core.Register(&collectors.H3C{})    // 暂不纳入采集，仅作示例
	// core.Register(&collectors.Huawei{}) // 暂不纳入采集，仅作示例

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	r.GET("/debug", func(ctx *gin.Context) {
		page := `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>netsec_exporter Debug</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Noto Sans", "Liberation Sans", sans-serif; margin: 16px; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; }
    .field { display: flex; flex-direction: column; gap: 6px; min-width: 260px; }
    input, select { padding: 8px; font-size: 14px; }
    button { padding: 8px 12px; font-size: 14px; cursor: pointer; }
    pre { background: #0b1020; color: #e6e6e6; padding: 12px; overflow: auto; border-radius: 6px; }
    .muted { color: #666; font-size: 12px; }
  </style>
</head>
<body>
  <h2>netsec_exporter 调试</h2>
  <div class="muted">填写 target/vendor/type/auth 后点击 Probe，即可请求 /probe 并展示返回的 metrics。</div>
  <div style="height: 12px"></div>

  <div class="row">
    <div class="field">
      <label for="target">target</label>
      <input id="target" placeholder="192.168.254.1" />
    </div>
    <div class="field">
      <label for="vendor">vendor</label>
      <input id="vendor" placeholder="sangfor / dbapp" list="vendorList" />
      <datalist id="vendorList">
        <option value="sangfor"></option>
        <option value="dbapp"></option>
      </datalist>
    </div>
    <div class="field">
      <label for="type">type</label>
      <input id="type" placeholder="firewall" list="typeList" />
      <datalist id="typeList">
        <option value="firewall"></option>
      </datalist>
    </div>
    <div class="field">
      <label for="auth">auth</label>
      <input id="auth" placeholder="auth id in auth_file (e.g. sangfor_admin)" />
    </div>
    <div class="field">
      <label for="name">name (optional)</label>
      <input id="name" placeholder="sangfor-fw-01" />
    </div>
  </div>

  <div style="height: 12px"></div>
  <div class="row">
    <button id="btnProbe">Probe (fetch)</button>
    <button id="btnOpen">Open /probe</button>
  </div>

  <div style="height: 12px"></div>
  <div class="muted">Request URL</div>
  <pre id="url"></pre>

  <div class="muted">Response</div>
  <pre id="out"></pre>

<script>
  function buildURL() {
    const target = document.getElementById('target').value.trim();
    const vendor = document.getElementById('vendor').value.trim();
    const type = document.getElementById('type').value.trim();
    const auth = document.getElementById('auth').value.trim();
    const name = document.getElementById('name').value.trim();
    const params = new URLSearchParams();
    if (target) params.set('target', target);
    if (vendor) params.set('vendor', vendor);
    if (type) params.set('type', type);
    if (auth) params.set('auth', auth);
    if (name) params.set('name', name);
    return '/probe?' + params.toString();
  }

  function refreshURL() {
    document.getElementById('url').textContent = buildURL();
  }

  ['target','vendor','type','auth','name'].forEach(id => {
    document.getElementById(id).addEventListener('input', refreshURL);
  });
  refreshURL();

  document.getElementById('btnOpen').addEventListener('click', () => {
    const u = buildURL();
    document.getElementById('out').textContent = '';
    window.open(u, '_blank');
  });

  document.getElementById('btnProbe').addEventListener('click', async () => {
    const u = buildURL();
    document.getElementById('out').textContent = 'Loading...';
    try {
      const resp = await fetch(u, { method: 'GET' });
      const text = await resp.text();
      document.getElementById('out').textContent = text;
    } catch (e) {
      document.getElementById('out').textContent = String(e);
    }
  });
</script>
</body>
</html>`
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
	})
	r.GET("/probe", func(ctx *gin.Context) {
		target := strings.TrimSpace(ctx.Query("target"))
		vendor := strings.TrimSpace(ctx.Query("vendor"))
		devType := strings.TrimSpace(ctx.Query("type"))
		name := strings.TrimSpace(ctx.Query("name"))
		authID := strings.TrimSpace(ctx.Query("auth"))

		if target == "" || vendor == "" || devType == "" {
			ctx.String(http.StatusBadRequest, "missing required params: target, vendor, type\n")
			return
		}
		if name == "" {
			name = target
		}

		dev := core.Device{
			Name:   name,
			Host:   target,
			Vendor: vendor,
			Type:   devType,
		}

		if authID == "" {
			ctx.String(http.StatusBadRequest, "missing required param: auth\n")
			return
		}
		a, ok := auths[authID]
		if !ok {
			ctx.String(http.StatusBadRequest, "unknown auth: %s\n", authID)
			return
		}
		if a.Vendor != "" && a.Vendor != vendor {
			ctx.String(http.StatusBadRequest, "auth vendor mismatch: %s\n", authID)
			return
		}
		if a.Type != "" && a.Type != devType {
			ctx.String(http.StatusBadRequest, "auth type mismatch: %s\n", authID)
			return
		}
		dev.Token = a.Token
		dev.Username = a.Username
		dev.Password = a.Password

		if dev.Token == "" && dev.Username == "" && dev.Password == "" {
			ctx.String(http.StatusBadRequest, "auth has no credentials: %s\n", authID)
			return
		}

		reg := prometheus.NewRegistry()
		reg.MustRegister(&probeCollector{device: dev})

		handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
		handler.ServeHTTP(ctx.Writer, ctx.Request)
	})

	log.Printf("Starting netsec_exporter, listen on %s", config.Metrics.Listen)
	if err := r.Run(config.Metrics.Listen); err != nil {
		log.Fatalf("failed to run server: %v", err)
	}
}
