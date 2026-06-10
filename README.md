# Netsec Exporter

`netsec_exporter` 是一个通用的网络安全设备 Prometheus 指标采集器，旨在为不同品牌（Vendor）和不同类型（Type）的安全设备提供统一的监控方案。

## 核心特性

- **多品牌支持**：采用插件化设计，支持安恒 (DBAPP)、奇安信 (QiAnXin)、深信服 (Sangfor)、飞塔 (Fortinet)、山石网科 (Hillstone)、华三 (H3C)、华为 (Huawei) 等厂商。
- **设备类型细分**：支持在品牌下细分设备类型，如明御防火墙 (DASTGFW)、WAF、堡垒机等。
- **多目标采集**：提供 `/probe` 接口，Prometheus 通过 scrape_configs（静态/文件发现）传入 target/vendor/type/auth，实现类似 snmp_exporter 的多目标采集。
- **自动化部署**：支持通过命令行参数一键安装为 Systemd 服务。
- **指标通用化**：采用 `netsec_` 前缀的统一指标命名规范。

## 使用说明

### 1. 编译程序
在项目根目录执行以下命令进行编译：
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o netsec_exporter_ubuntu22_amd64 ./main.go
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o netsec_exporter_centos7_amd64 ./main.go
```

### 2. 运行说明
二进制文件默认读取当前目录下的 `config.yaml`。您也可以通过 `-config` 参数指定路径：
```bash
# 默认读取当前目录的 config.yaml
./netsec_exporter_ubuntu22_amd64

# 指定配置文件路径
./netsec_exporter_ubuntu22_amd64 -config /etc/netsec/config.yaml
```

### 3. 配置说明
编辑 `config.yaml` 文件，配置全局参数与认证文件路径。
```yaml
global:
  timeout: 10               # 请求超时（秒）
  insecure_skip_verify: true # 跳过 TLS 验证
  max_concurrent_probes: 20 # /probe 最大并发数（用于保护 Exporter 与设备）
  max_concurrent_probes_per_target: 1 # 单个 target 最大并发数（避免同一台设备被并发打爆）
  enable_debug_page: true   # 是否开启 /probe 无参数时的 Web 调试页
  auth_reload_interval_seconds: 5 # auth_file 热加载检测间隔（秒）
  allowed_vendors: []       # 允许的 vendor 白名单（空表示不限制）
  allowed_types: []         # 允许的 type 白名单（空表示不限制）

metrics:
  listen: ":9808"

auth_file: "/etc/netsec/auth.yaml"
```

### 3.1 多目标（/probe）模式与认证配置
Exporter 支持类似 `snmp_exporter` 的多目标采集模式：Prometheus 在 scrape 时通过 query params 指定 `target/vendor/type/auth`，Exporter 在单次请求内完成采集并返回该目标的指标。

#### 认证信息放置与引用（推荐）
建议将认证信息放在 Exporter 本机文件（`auth_file`）中，通过 `auth` 参数引用，避免把 token/密码写入 Prometheus 配置或 URL。

`config.yaml` 增加：
```yaml
auth_file: /etc/netsec/auth.yaml
```

`/etc/netsec/auth.yaml` 示例：
```yaml
auths:
  sangfor_admin:
    vendor: sangfor
    type: firewall
    username: admin
    password: your-password

  dbapp_token_a:
    vendor: dbapp
    type: firewall
    token: your-api-token
```

#### /probe 参数说明
- `target`：设备 IP/地址（必填）
- `vendor`：品牌（必填，例如 `sangfor`/`dbapp`）
- `type`：设备类型（必填，例如 `firewall`）
- `auth`：认证引用 ID（必填，来自 `auth_file`）
- `name`：设备名称（可选，不填默认使用 target）

#### Web 调试页
可访问 `http://<exporter>:9808/probe`（不带 query 参数）在页面中填写 `target/vendor/type/auth` 并直接发起探测请求。

### 3.2 深信服 HCI / SCP API 说明
- **版本说明**：从 HCI 6.8.0 开始，新建集群不再支持使用 HCI 的 API，必须使用 SCP 的 API 接口（本文档接口以 `/janus/...` 为主）。
- **Cookie 说明**：SCP 6.3.70 及以上版本已经无需再传入 Cookie。Exporter 的实现不会依赖 Cookie（为兼容老版本接口可能会附带随机 `aCMPAuthToken`，一般不影响请求）。
- **认证请求头**：`Authorization: {认证方式} {认证参数}`
  - 支持 `AWS4-HMAC-SHA256`（EC2 签名）
  - 支持 `Token`（示例：`Authorization: Token <token_id>`）

### 4. Prometheus 配置示例（static_configs）
以下示例使用 `static_configs` 管理多台设备，并通过 relabel 将 labels 转成 `/probe` 参数：

```yaml
scrape_configs:
  - job_name: netsec_fw_probe
    metrics_path: /probe
    static_configs:
      - targets:
          - 192.168.254.1
          - 192.168.254.2
        labels:
          vendor: sangfor
          type: firewall
          auth: sangfor_admin

      - targets:
          - 10.18.130.212
        labels:
          vendor: dbapp
          type: firewall
          auth: dbapp_token_a

    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [vendor]
        target_label: __param_vendor
      - source_labels: [type]
        target_label: __param_type
      - source_labels: [auth]
        target_label: __param_auth
      - source_labels: [__address__]
        target_label: instance
      - source_labels: [__address__]
        target_label: device_name
      - target_label: __address__
        replacement: netsec-exporter:9808
```

### 5. Prometheus 配置示例（file_sd_configs）
适合大量设备时，将 targets 放入文件由 Prometheus 自动加载：

Prometheus 配置：
```yaml
scrape_configs:
  - job_name: netsec_fw_probe
    metrics_path: /probe
    file_sd_configs:
      - files:
          - /etc/prometheus/netsec_targets/*.yaml
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [vendor]
        target_label: __param_vendor
      - source_labels: [type]
        target_label: __param_type
      - source_labels: [auth]
        target_label: __param_auth
      - source_labels: [name]
        target_label: device_name
      - source_labels: [__address__]
        target_label: instance
      - target_label: __address__
        replacement: netsec-exporter:9808
```

`/etc/prometheus/netsec_targets/fw.yaml` 示例：
```yaml
- targets: ["192.168.254.1"]
  labels:
    name: sangfor-fw-01
    vendor: sangfor
    type: firewall
    auth: sangfor_admin

- targets: ["10.18.130.212"]
  labels:
    name: dbapp-fw-01
    vendor: dbapp
    type: firewall
    auth: dbapp_token_a
```

### 6. 自动安装服务
执行以下命令自动生成并安装 Systemd 服务文件（**需要 root 权限**）：
```bash
sudo ./netsec_exporter_ubuntu22_amd64 --install
```

### 7. 管理服务
安装成功后，程序会提示您执行以下标准 systemd 命令来管理服务：
```bash
# 重新加载系统服务配置
systemctl daemon-reload
# 设置开机自启动
systemctl enable netsec_exporter
# 启动服务
systemctl start netsec_exporter
# 查看服务状态
systemctl status netsec_exporter
# 停止服务
systemctl stop netsec_exporter
```

### 8. Service 配置说明
通过 `--install` 自动生成的 `/etc/systemd/system/netsec_exporter.service` 包含以下关键配置：
- **WorkingDirectory**: 自动设置为二进制文件所在的目录，确保 `config.yaml` 能被正确读取。
- **ExecStart**: 自动设置为二进制文件的绝对路径。
- **Restart**: 设置为 `always`，确保程序崩溃后能自动重启，提高可靠性。

## HTTP 接口
- `/metrics`：Exporter 自身指标（Prometheus 默认 handler）
- `/probe`：多目标采集入口（Prometheus 通过 scrape_configs 传入 target/vendor/type/auth）
- `/probe`（不带 query 参数）：Web 调试页（表单方式调用 /probe）

## 导出指标说明

备注：风扇、电源、温度相关指标在深信服 8.0.107 及以上版本才支持。

| 指标名称 | 类型 | 含义 | 标签 |
| :--- | :--- | :--- | :--- |
| `netsec_device_up` | Gauge | 设备在线状态 | `device_name, instance, vendor, role` |
| `netsec_scrape_duration_seconds` | Gauge | 每次采集耗时（秒） | `device_name, instance, vendor, role` |
| `netsec_system_cpu_usage_percent` | Gauge | CPU 使用率（百分比） | `device_name, instance, vendor, role` |
| `netsec_system_memory_usage_percent` | Gauge | 内存使用率（百分比） | `device_name, instance, vendor, role` |
| `netsec_system_disk_usage_percent` | Gauge | 硬盘使用率（百分比） | `device_name, instance, vendor, role` |
| `netsec_system_version_info` | Gauge | 系统版本信息（成功=1，失败=0；版本通过 `version` 标签暴露） | `device_name, instance, vendor, role[, version]` |
| `netsec_system_uptime_seconds` | Gauge | 设备持续运行时间（秒） | `device_name, instance, vendor, role` |
| `netsec_system_boot_time_seconds` | Gauge | 设备启动时间（Unix 时间戳，秒） | `device_name, instance, vendor, role` |
| `netsec_session_active_current` | Gauge | 实时活跃/并发会话数（当前值） | `device_name, instance, vendor, role` |
| `netsec_sessions_new_per_second` | Gauge | 实时新建会话速率（每秒） | `device_name, instance, vendor, role` |
| `netsec_session_max_limit` | Gauge | 最大会话数上限（部分厂商不支持则不输出） | `device_name, instance, vendor, role` |
| `netsec_ha_enabled` | Gauge | HA 是否开启（1:开启, 0:关闭） | `device_name, instance, vendor, role` |
| `netsec_ha_mode` | Gauge | HA 模式（ACTIVE-ACTIVE=1, ACTIVE-PASSIVE=2, MIRROR=3） | `device_name, instance, vendor, role` |
| `netsec_system_fan_status` | Gauge | 风扇传感器状态（Normal=1, Abnormal=0） | `device_name, instance, vendor, role, sensor_name` |
| `netsec_system_power_status` | Gauge | 电源传感器状态（Normal=1, Abnormal=0） | `device_name, instance, vendor, role, sensor_name` |
| `netsec_system_temperature_status` | Gauge | 温度传感器状态（Normal=1, Abnormal=0） | `device_name, instance, vendor, role, sensor_name` |
| `netsec_system_temperature_current_celsius` | Gauge | 温度传感器当前温度（摄氏度） | `device_name, instance, vendor, role, sensor_name` |
| `netsec_system_temperature_min_celsius` | Gauge | 温度传感器告警下限（摄氏度） | `device_name, instance, vendor, role, sensor_name` |
| `netsec_system_temperature_max_celsius` | Gauge | 温度传感器告警上限（摄氏度） | `device_name, instance, vendor, role, sensor_name` |
| `netsec_interface_send_bits` | Gauge | 设备维度：总实时发送速率（bits） | `device_name, instance, vendor, role` |
| `netsec_interface_recv_bits` | Gauge | 设备维度：总实时接收速率（bits） | `device_name, instance, vendor, role` |
| `netsec_interface_physical_state` | Gauge | 接口物理状态（true=1, false=0） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_link_state` | Gauge | 接口链路状态（true=1, false=0） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_mtu_bytes` | Gauge | 接口 MTU（bytes） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_ping_up` | Gauge | 接口 Ping 开关/可用（true=1, false=0） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_role` | Gauge | 接口角色（WAN=1, 非 WAN=0） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_media_type` | Gauge | 介质类型（TP=0, FIBER=1） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_category` | Gauge | 接口类别（PHYSICALIF=1, else=0） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_layer_mode` | Gauge | 接口层模式（BRIDGE=0, ROUTE=1） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_speed_mbps` | Gauge | 双工下协商速率（Mbps） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_traffic_out_bps` | Gauge | 接口出方向速率（bps） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_traffic_in_bps` | Gauge | 接口入方向速率（bps） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_traffic_out_packets_total` | Gauge | 接口出方向包数（当前值） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_interface_traffic_in_packets_total` | Gauge | 接口入方向包数（当前值） | `device_name, instance, vendor, role, if_name, description, zone, mac, ip_addr` |
| `netsec_iplink_status` | Gauge | IPLink 状态（1:正常, 0:异常） | `device_name, instance, vendor, role, name, interface, destination` |

## 开发者指南

### 扩展新厂商/设备
1. 在 `collectors/` 目录下创建新的厂商文件（如 `collectors/new_vendor.go`）。
2. 实现 `core.Collector` 接口：
   - `Name() string`: 返回厂商标识。
   - `Supported(dev core.Device) bool`: 判断是否支持该设备。
   - `Collect(dev core.Device) ([]core.Metric, error)`: 实现具体的 API 调用和指标转换逻辑。
3. 在 `main.go` 中调用 `core.Register()` 注册新插件。

## 许可证
[MIT License](LICENSE)
