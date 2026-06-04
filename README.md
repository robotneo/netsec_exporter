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
  interval: 60              # 采集周期（秒）（仅用于兼容字段，/probe 模式不会按 interval 定时采集）
  timeout: 10               # 请求超时（秒）
  workers: 20               # 并发协程数（仅用于兼容字段，/probe 模式不使用 worker pool）
  insecure_skip_verify: true # 跳过 TLS 验证

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
可访问 `http://<exporter>:9808/debug` 在页面中填写 `target/vendor/type/auth` 并直接发起探测请求。

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
        target_label: host
      - source_labels: [__address__]
        target_label: device
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
        target_label: device
      - source_labels: [__address__]
        target_label: host
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
- `/debug`：Web 调试页（表单方式调用 /probe）

## 导出指标说明

| 指标名称 | 类型 | 含义 | 标签 |
| :--- | :--- | :--- | :--- |
| `netsec_device_up` | Gauge | 设备在线状态 (1:正常, 0:异常) | `device, host, vendor, type` |
| `netsec_iplink_status` | Gauge | IPLink 状态 (1:正常, 0:异常) | `device, host, vendor, type, name, interface, destination` |
| `netsec_cpu_usage_percent` | Gauge | CPU 使用率（百分比） | `device, host, vendor, type` |
| `netsec_memory_usage_percent` | Gauge | 内存使用率（百分比） | `device, host, vendor, type` |
| `netsec_disk_usage_percent` | Gauge | 硬盘使用率（百分比） | `device, host, vendor, type` |
| `netsec_session_concurrent` | Gauge | 实时并发会话数（单位：session） | `device, host, vendor, type` |
| `netsec_session_creation_rate` | Gauge | 实时新建会话数（单位：session） | `device, host, vendor, type` |
| `netsec_interface_send_bits` | Gauge | 接口总实时发送速率（单位：bits） | `device, host, vendor, type` |
| `netsec_interface_recv_bits` | Gauge | 接口总实时接收速率（单位：bits） | `device, host, vendor, type` |
| `netsec_ha_enabled` | Gauge | HA 是否开启（1:开启, 0:关闭） | `device, host, vendor, type` |
| `netsec_ha_mode` | Gauge | HA 模式（ACTIVE-ACTIVE=1, ACTIVE-PASSIVE=2, MIRROR=3） | `device, host, vendor, type` |
| `netsec_scrape_duration_seconds` | Gauge | 每次采集耗时（秒） | `device, host, vendor, type` |

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
