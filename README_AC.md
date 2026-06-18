# 深信服 AC（行为管理设备）采集说明

本文档描述 `netsec_exporter` 对深信服 AC（行为管理设备，`vendor=sangfor`，`type=ac`）的采集指标与配置方式。

## /probe 参数

- `vendor`: `sangfor`
- `type`: `ac`
- `target`: 设备地址（IP/域名；如需指定端口用 `host:port`，端口来自 `auth_file` 的 `ac_port`）
- `auth`: `auth_file` 中的认证条目 ID
- `name`: 可选，设备名称（不填则默认使用 target）

示例：

```
/probe?target=192.168.1.1&vendor=sangfor&type=ac&auth=sangfor_ac_01&name=ac-01
```

## 认证配置（auth_file）

`config.yaml` 中指定：

```yaml
auth_file: /etc/netsec/auth.yaml
```

`/etc/netsec/auth.yaml` 示例：

```yaml
auths:
  sangfor_ac_01:
    vendor: sangfor
    type: ac
    shared_key: "your-shared-key"
    ac_port: 9999
    snmp_community: "public"
    snmp_port: 161
```

字段说明：

- `shared_key`：AC API 鉴权使用的共享密钥（必填）
- `ac_port`：AC API 端口（可选，默认 `9999`）
- `snmp_community`：SNMP v2c community（可选；用于“容量上限/接口表”类指标）
- `snmp_port`：SNMP 端口（可选，默认 `161`）

## 鉴权方式说明

- `random`：16 位纯数字随机串，Exporter 会缓存并在 1 小时内复用同一个 `random`
- `md5`：`MD5(shared_key + random)`（小写 hex）
- GET 接口：`random`/`md5` 作为 query 参数追加
- POST 接口：`random`/`md5` 注入 JSON body

## 指标列表

通用标签（由 Exporter 自动补齐）：`device_name`、`instance`、`vendor`、`role`

### 系统与资源

- `netsec_system_version_info{version="..."}`：采集成功值为 1，失败为 0（API：`GET /v1/status/version`）
- `netsec_system_cpu_usage_percent`：CPU 使用率（API：`GET /v1/status/cpu-usage`）
- `netsec_system_memory_usage_percent`：内存使用率（API：`GET /v1/status/mem-usage`）
- `netsec_system_disk_usage_percent`：磁盘使用率（API：`GET /v1/status/disk-usage`）

### 会话

- `netsec_session_active_current`：当前会话数（API：`GET /v1/status/session-num`）
- `netsec_online_users_max_limit`：最大在线用户上限（SNMP：`.1.3.6.1.4.1.35047.2.1.1.2.0`；需配置 `snmp_community`）
- `netsec_session_max_limit`：最大会话上限（SNMP：`.1.3.6.1.4.1.35047.2.1.1.5.0`；需配置 `snmp_community`）

### WAN 吞吐与带宽

标签：`name="WAN"`

- `netsec_interface_send_bits{name="WAN"}`：总上行吞吐（bits/s，API：`POST /v1/status/throughput?_method=GET`）
- `netsec_interface_recv_bits{name="WAN"}`：总下行吞吐（bits/s，API：`POST /v1/status/throughput?_method=GET`）
- `netsec_bandwidth_usage_percent{name="WAN"}`：带宽使用率（API：`GET /v1/status/bandwidth-usage`）

### 接口表（SNMP）

标签：`if_name`（接口名称）以及 `description`、`zone`、`mac`、`ip_addr`（当前 AC 的 SNMP 表仅能提供 `if_name`，其余为空）

- `netsec_interface_link_state{if_name="..."}`：链路状态（1=开启/UP，0=关闭/DOWN）
  - ifName：`.1.3.6.1.4.1.35047.2.1.2.1.2`
  - ifLink：`.1.3.6.1.4.1.35047.2.1.2.1.4`
- `netsec_interface_traffic_out_bytes_total{if_name="..."}`：累计发送字节（bytes）
  - ifTxBytes：`.1.3.6.1.4.1.35047.2.1.2.1.7`
- `netsec_interface_traffic_in_bytes_total{if_name="..."}`：累计接收字节（bytes）
  - ifRxBytes：`.1.3.6.1.4.1.35047.2.1.2.1.8`
