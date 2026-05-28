# Netsec Exporter

`netsec_exporter` 是一个通用的网络安全设备 Prometheus 指标采集器，旨在为不同品牌（Vendor）和不同类型（Type）的安全设备提供统一的监控方案。

## 核心特性

- **多品牌支持**：采用插件化设计，支持安恒 (DBAPP)、奇安信 (QiAnXin)、深信服 (Sangfor)、飞塔 (Fortinet)、山石网科 (Hillstone)、华三 (H3C)、华为 (Huawei) 等厂商。
- **设备类型细分**：支持在品牌下细分设备类型，如明御防火墙 (DASTGFW)、WAF、堡垒机等。
- **高性能并发采集**：内置工作池（Worker Pool），支持对海量设备进行高效并发采集。
- **自动化部署**：支持通过命令行参数一键安装为 Systemd 服务。
- **指标通用化**：采用 `netsec_` 前缀的统一指标命名规范。

## 使用说明

### 1. 编译程序
在项目根目录执行以下命令进行编译：
```bash
go build -o netsec_exporter main.go
```

### 2. 运行说明
二进制文件默认读取当前目录下的 `config.yaml`。您也可以通过 `-config` 参数指定路径：
```bash
# 默认读取当前目录的 config.yaml
./netsec_exporter

# 指定配置文件路径
./netsec_exporter -config /etc/netsec/my_config.yaml
```

### 3. 配置说明
编辑 `config.yaml` 文件，配置全局参数和设备列表。
```yaml
global:
  interval: 60              # 采集周期（秒）
  timeout: 10               # 请求超时（秒）
  workers: 20               # 并发协程数
  insecure_skip_verify: true # 跳过 TLS 验证

devices:
  - name: my-firewall-01
    host: 192.168.1.1
    token: your-api-token
    vendor: dbapp           # 品牌：dbapp (安恒)
    type: dastgfw           # 类型：dastgfw (明御防火墙)
```

### 3. 自动安装服务
执行以下命令自动生成并安装 Systemd 服务文件（**需要 root 权限**）：
```bash
sudo ./netsec_exporter --install
```

### 4. 管理服务
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

### 5. Service 配置说明
通过 `--install` 自动生成的 `/etc/systemd/system/netsec_exporter.service` 包含以下关键配置：
- **WorkingDirectory**: 自动设置为二进制文件所在的目录，确保 `config.yaml` 能被正确读取。
- **ExecStart**: 自动设置为二进制文件的绝对路径。
- **Restart**: 设置为 `always`，确保程序崩溃后能自动重启，提高可靠性。

## 导出指标说明

| 指标名称 | 类型 | 含义 | 标签 |
| :--- | :--- | :--- | :--- |
| `netsec_device_up` | Gauge | 设备在线状态 (1:正常, 0:异常) | `device, vendor, type` |
| `netsec_iplink_status` | Gauge | IPLink 状态 (1:正常, 0:异常) | `device, vendor, type, name, interface, destination` |
| `netsec_scrape_duration_seconds` | Gauge | 每次采集耗时（秒） | `device, vendor, type` |

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
