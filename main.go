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
		"device_name": c.device.Name,
		"instance":    c.device.Host,
		"vendor":      c.device.Vendor,
		"type":        c.device.Type,
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
		"device_name": c.device.Name,
		"instance":    c.device.Host,
		"vendor":      c.device.Vendor,
		"type":        c.device.Type,
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
		all[i].Labels = core.NormalizeCommonLabels(all[i].Labels)
		if _, ok := all[i].Labels["device_name"]; !ok {
			all[i].Labels["device_name"] = c.device.Name
		}
		if _, ok := all[i].Labels["instance"]; !ok {
			all[i].Labels["instance"] = c.device.Host
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
	r.GET("/", func(ctx *gin.Context) {
		page := `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetSec Exporter</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Noto Sans", "Liberation Sans", sans-serif; margin: 16px; }
    a { text-decoration: none; }
    .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; max-width: 720px; }
    .row { display: flex; gap: 12px; flex-wrap: wrap; }
    .link { display: inline-block; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; }
    .muted { color: #666; font-size: 12px; margin-top: 8px; }
  </style>
</head>
<body>
  <h1>NetSec Exporter</h1>
  <div class="card">
    <div class="row">
      <a class="link" href="/metrics">/metrics</a>
      <a class="link" href="/probe">/probe</a>
    </div>
    <div class="muted">/metrics：采集器本身指标；/probe：多目标采集入口（无参数时为调试页）。</div>
  </div>
</body>
</html>`
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
	})
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	debugPage := func(ctx *gin.Context) {
		page := `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetSec Exporter Debug</title>
  <style>
    :root {
      --bg0: #f8fafc;
      --bg1: #eef2ff;
      --card: rgba(255,255,255,.75);
      --stroke: rgba(15,23,42,.10);
      --text: #0f172a;
      --muted: rgba(15,23,42,.65);
      --primary: #2563eb;
      --primary2: #7c3aed;
      --shadow: 0 16px 45px rgba(2,6,23,.12);
      --ring: 0 0 0 4px rgba(37,99,235,.18);
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }

    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Noto Sans", "Liberation Sans", sans-serif;
      color: var(--text);
      background: radial-gradient(900px circle at 15% 10%, rgba(124,58,237,.20), transparent 60%),
                  radial-gradient(800px circle at 80% 20%, rgba(37,99,235,.18), transparent 55%),
                  linear-gradient(180deg, var(--bg0), var(--bg1));
    }
    a { color: inherit; text-decoration: none; }

    .container { max-width: 1120px; margin: 0 auto; padding: 22px 18px 34px; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .brand { display: flex; flex-direction: column; gap: 6px; }
    .title { font-size: 22px; font-weight: 750; letter-spacing: .2px; margin: 0; }
    .subtitle { color: var(--muted); font-size: 13px; margin: 0; line-height: 1.4; }

    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 10px;
      border-radius: 999px;
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,.65);
      backdrop-filter: blur(10px);
      box-shadow: 0 8px 24px rgba(2,6,23,.08);
      font-size: 12px;
      color: var(--muted);
      white-space: nowrap;
    }
    .status-dot { width: 8px; height: 8px; border-radius: 999px; background: #94a3b8; }
    .status-dot.ok { background: #10b981; }
    .status-dot.loading { background: #2563eb; }
    .status-dot.err { background: #ef4444; }

    .grid { margin-top: 16px; display: grid; grid-template-columns: 1fr; gap: 14px; }
    @media (min-width: 980px) { .grid { grid-template-columns: 0.9fr 1.1fr; } }

    .card {
      border: 1px solid var(--stroke);
      background: var(--card);
      backdrop-filter: blur(12px);
      border-radius: 14px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    .card-hd { padding: 14px 14px 0; }
    .card-bd { padding: 14px; }
    .card-title { margin: 0; font-size: 14px; font-weight: 700; }
    .card-desc { margin: 6px 0 0; font-size: 12px; color: var(--muted); line-height: 1.45; }

    .form { display: grid; grid-template-columns: 1fr; gap: 12px; margin-top: 4px; }
    @media (min-width: 640px) { .form { grid-template-columns: 1fr 1fr; } }
    .field { display: flex; flex-direction: column; gap: 7px; }
    .field.wide { grid-column: 1 / -1; }
    label { font-size: 12px; color: var(--muted); letter-spacing: .2px; }
    input, select {
      appearance: none;
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,.85);
      border-radius: 10px;
      padding: 10px 11px;
      font-size: 14px;
      color: var(--text);
      outline: none;
      transition: box-shadow .18s ease, border-color .18s ease, transform .18s ease;
    }
    input:focus, select:focus { box-shadow: var(--ring); border-color: rgba(37,99,235,.55); }

    .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
    button {
      border: 1px solid var(--stroke);
      background: rgba(255,255,255,.75);
      border-radius: 11px;
      padding: 10px 12px;
      font-size: 14px;
      font-weight: 650;
      cursor: pointer;
      transition: transform .12s ease, box-shadow .18s ease, background .18s ease;
    }
    button:hover { transform: translateY(-1px); box-shadow: 0 10px 30px rgba(2,6,23,.12); }
    button:active { transform: translateY(0); box-shadow: none; }
    .btn-primary {
      border-color: rgba(37,99,235,.35);
      color: white;
      background: linear-gradient(135deg, var(--primary), var(--primary2));
    }
    .btn-ghost { background: rgba(255,255,255,.55); }

    .split { display: grid; grid-template-columns: 1fr; gap: 14px; }
    pre {
      margin: 0;
      font-family: var(--mono);
      background: rgba(241,245,249,.85);
      border: 1px solid var(--stroke);
      border-radius: 12px;
      padding: 12px;
      overflow: auto;
      max-height: 420px;
      color: #0b1220;
      line-height: 1.45;
      font-size: 12px;
    }
    .kv { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: 0 0 8px; }
    .kv .k { font-size: 12px; color: var(--muted); }
    .kv .v { font-size: 12px; color: var(--muted); }
    .hint { margin-top: 10px; font-size: 12px; color: var(--muted); }
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div class="brand">
        <h1 class="title">NetSec Exporter 调试</h1>
        <p class="subtitle">填写 target/vendor/type/auth 后点击 Probe，即可请求 /probe 并展示返回的 metrics。</p>
      </div>
      <div class="pill">
        <span id="statusDot" class="status-dot"></span>
        <span id="statusText">Idle</span>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-hd">
          <p class="card-title">Probe 参数</p>
          <p class="card-desc">vendor/type 用于选择采集插件；auth 从 auth_file 中选择凭据。</p>
        </div>
        <div class="card-bd">
          <div class="form">
            <div class="field wide">
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

          <div class="actions">
            <button class="btn-primary" id="btnProbe">Probe</button>
            <button class="btn-ghost" id="btnOpen">打开 /probe</button>
          </div>

          <div class="hint">
            快捷入口：<a href="/metrics">/metrics</a>
          </div>
        </div>
      </div>

      <div class="split">
        <div class="card">
          <div class="card-bd">
            <div class="kv">
              <div class="k">Request URL</div>
              <div class="v">GET</div>
            </div>
            <pre id="url"></pre>
          </div>
        </div>

        <div class="card">
          <div class="card-bd">
            <div class="kv">
              <div class="k">Response</div>
              <div class="v" id="respMeta"></div>
            </div>
            <pre id="out"></pre>
          </div>
        </div>
      </div>
    </div>
  </div>

<script>
  function setStatus(state, text) {
    const dot = document.getElementById('statusDot');
    const t = document.getElementById('statusText');
    dot.className = 'status-dot' + (state ? ' ' + state : '');
    t.textContent = text || 'Idle';
  }

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
  setStatus('', 'Idle');
  refreshURL();

  document.getElementById('btnOpen').addEventListener('click', () => {
    const u = buildURL();
    document.getElementById('out').textContent = '';
    document.getElementById('respMeta').textContent = '';
    window.open(u, '_blank');
  });

  document.getElementById('btnProbe').addEventListener('click', async () => {
    const u = buildURL();
    setStatus('loading', 'Loading');
    document.getElementById('respMeta').textContent = '';
    document.getElementById('out').textContent = 'Loading...';
    try {
      const resp = await fetch(u, { method: 'GET' });
      const text = await resp.text();
      document.getElementById('respMeta').textContent = resp.status + ' ' + (resp.ok ? 'OK' : 'ERROR');
      document.getElementById('out').textContent = text;
      setStatus(resp.ok ? 'ok' : 'err', resp.ok ? 'OK' : 'Error');
    } catch (e) {
      document.getElementById('respMeta').textContent = 'FETCH ERROR';
      document.getElementById('out').textContent = String(e);
      setStatus('err', 'Error');
    }
  });
</script>
</body>
</html>`
		ctx.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
	}

	r.GET("/probe", func(ctx *gin.Context) {
		if strings.TrimSpace(ctx.Request.URL.RawQuery) == "" {
			debugPage(ctx)
			return
		}

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
