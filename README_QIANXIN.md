# 奇安信网神防火墙采集说明

本文档描述 `netsec_exporter` 对奇安信网神防火墙（`vendor=qianxin`，`type=firewall`）当前已实现的采集方式、认证配置与指标列表。

## /probe 参数

- `vendor`: `qianxin`
- `type`: `firewall`
- `target`: 设备地址
- `auth`: `auth_file` 中的认证条目 ID
- `name`: 可选，设备名称（不填则默认使用 target）

示例：

```text
/probe?target=http://172.18.6.253:8080&vendor=qianxin&type=firewall&auth=qianxin_fw_01&name=qax-fw-01
```

说明：

- 如果设备使用 `http://` 或非默认端口，建议在 `target` 中写完整地址，例如 `http://172.18.6.253:8080`
- 如果只写 `172.18.6.253:8080`，当前 client 会默认补成 `https://`

## 认证配置（auth_file）

`config.yaml` 中指定：

```yaml
auth_file: /etc/netsec/auth.yaml
```

`/etc/netsec/auth.yaml` 示例：

```yaml
auths:
  qianxin_fw_01:
    vendor: qianxin
    type: firewall
    username: "admin"
    password: "your-password"
```

字段说明：

- `username`：登录用户名，必填
- `password`：登录密码，必填

可选写法：

```yaml
auths:
  qianxin_fw_02:
    vendor: qianxin
    type: firewall
    username: "admin"
    password: "your-password"
    token: "existing-token"
```

说明：

- 当前支持通过 `POST /v1.0/login` 获取 `token`
- 后续请求会自动携带 `username + token + Cookie`
- 如果会话过期，Exporter 会自动重新登录再重试一次
- 为保证自动重登生效，建议始终配置 `username + password`

## 标签说明

- 通用标签（由 Exporter 自动补齐）：`device_name`、`instance`、`vendor`、`role`
- 网神当前还会补充：
  - `hostname`：从 `get_system_info` 返回中提取，并统一回填到所有指标
- 资源类部件标签：
  - `entity_name`
- HA 标签：
  - `ha`
- 接口标签：
  - `if_name`
  - `description`
  - `zone`
  - `mac`
  - `ip_addr`

## 指标列表（当前已实现）

### 系统信息

- `netsec_system_version_info{version="...",hostname="..."}`
  - 系统版本信息
  - 成功时值为 `1`
  - API：`dashboard/get_system_info`

- `netsec_ha_status{ha="...",hostname="..."}`
  - HA 状态
  - 指标值优先解析 `ha` 字段前缀数字；若无法解析则回退为 `1`
  - API：`dashboard/get_system_info`

### CPU / 内存 / 磁盘 / 风扇 / 电源

以下指标主要来自：

- API：`dashboard/get_system_resource`

CPU：

- `netsec_system_cpu_usage_percent{entity_name="cpu0",hostname="..."}`
  - CPU 使用率（%）

内存：

- `netsec_system_memory_usage_percent{entity_name="system",hostname="..."}`
  - 内存使用率（%）
- `netsec_system_memory_total_bytes{entity_name="system",hostname="..."}`
  - 内存总容量（bytes）
- `netsec_system_memory_used_bytes{entity_name="system",hostname="..."}`
  - 内存已用容量（bytes）
- `netsec_system_memory_free_bytes{entity_name="system",hostname="..."}`
  - 内存空闲容量（bytes）

说明：

- 设备返回的内存总量按 `KiB` 解释并转换为 `bytes`

磁盘：

- `netsec_system_disk_usage_percent{entity_name="cf",hostname="..."}`
- `netsec_system_disk_usage_percent{entity_name="ssd",hostname="..."}`
  - 磁盘使用率（%）

风扇：

- `netsec_system_fan_status{entity_name="CPU0 Fan",hostname="..."}`
  - 风扇状态，`1=正常`，`0=异常`
- `netsec_system_fan_speed_rpm{entity_name="CPU0 Fan",hostname="..."}`
  - 风扇转速（RPM）

电源：

- `netsec_system_power_status{entity_name="Power",hostname="..."}`
  - 电源状态，`1=normal`，`0=abnormal`
- `netsec_system_power_capacity_watts{entity_name="Power",hostname="..."}`
  - 电源功率/容量（watts）

### 会话类指标

以下指标来自：

- API：`statistics/get_connection_monitor`

- `netsec_sessions_new_per_second{hostname="..."}`
  - 新建连接数
  - 取 `sessions_new` 数组最后一个值，即最新时间戳对应值

- `netsec_session_active_current{hostname="..."}`
  - 并发连接数
  - 取 `sessions` 数组最后一个值，即最新时间戳对应值

### 接口基础信息

以下指标来自：

- API：`inter_face/show_all_interface_web`

- `netsec_interface_physical_state{if_name="...",description="...",zone="...",mac="...",ip_addr="...",hostname="..."}`
  - 接口启用状态，`1=enable`，`0=disable`

- `netsec_interface_link_state{...}`
  - 接口链路状态，`1=up`，`0=down`

- `netsec_interface_mtu_bytes{...}`
  - 接口 MTU（bytes）

- `netsec_interface_speed_mbps{...}`
  - 接口协商速率（Mbps）

- `netsec_interface_role{...}`
  - 接口角色，当前按 `is_wan` 映射，`WAN=1`，其他值为 `0`

- `netsec_interface_layer_mode{...}`
  - 接口层模式，`layer3=1`，`layer2=0`

### 接口流量

以下指标来自：

- API：`dashboard/get_interface_info`

- `netsec_interface_traffic_in_bps{if_name="...",description="...",zone="...",mac="...",ip_addr="...",hostname="..."}`
  - 接口流入速率（bps）

- `netsec_interface_traffic_out_bps{if_name="...",description="...",zone="...",mac="...",ip_addr="...",hostname="..."}`
  - 接口流出速率（bps）

说明：

- 当前支持解析 `bps / Kbps / Mbps / Gbps` 并统一换算为 `bps`
- 若 `get_interface_info` 返回中缺少完整接口元数据，会优先复用 `show_all_interface_web` 已获取到的标签

## 当前未实现

以下能力目前在网神防火墙采集中尚未实现：

- 温度类指标
- 接口累计字节 / 包数 / 错包 / 丢包
- 用户类指标
- 日志类指标
- 策略类指标
- VPN 类指标
