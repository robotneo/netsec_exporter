# 深信服 AD（应用交付 / ADC）采集说明

本文档描述 `netsec_exporter` 对深信服 AD（`vendor=sangfor`，`type=ad`）的当前采集指标与配置方式。

## /probe 参数

- `vendor`: `sangfor`
- `type`: `ad`
- `target`: 设备地址（IP/域名）
- `auth`: `auth_file` 中的认证条目 ID
- `name`: 可选，设备名称（不填则默认使用 target）

示例：

```
/probe?target=192.168.1.1&vendor=sangfor&type=ad&auth=sangfor_ad_01&name=ad-01
```

## 认证配置（auth_file）

AD 当前指标均通过 SNMP v2c 获取，因此需要在 `auth_file` 中配置 SNMP community。

`config.yaml` 中指定：

```yaml
auth_file: /etc/netsec/auth.yaml
```

`/etc/netsec/auth.yaml` 示例：

```yaml
auths:
  sangfor_ad_01:
    vendor: sangfor
    type: ad
    snmp_community: "public"
    snmp_port: 161
```

字段说明：

- `snmp_community`：SNMP v2c community（必填）
- `snmp_port`：SNMP 端口（可选，默认 161）

## 标签说明

- 通用标签（由 Exporter 自动补齐）：`device_name`、`instance`、`vendor`、`role`
- AD 采集会额外读取 `sysName.0` 并写入 `device_name=sysName`，用于与设备侧名称一致

## 指标列表（当前已实现）

说明：

- 所有标量/表指标均继承 `device_name=sysName`
- 表指标会增加表索引标签（如 `cpu_index`、`disk_index`、`fan_index`、`power_index`、`link_index`、`if_index`）以及对应名称标签（如 `part_name`、`fan_name`、`power_name`、`link_name`、`if_name`）

### 系统与资源（SNMP）

- `netsec_system_device_status{device_name="..."}`
  - 系统状态：`0=warning`，`1=normal`
  - OID：`.1.3.6.1.4.1.35047.1.12.0`（`sfDeviceStatus.0`）

- `netsec_system_uptime_seconds{device_name="..."}`
  - 系统启动时长（秒）
  - OID：`.1.3.6.1.4.1.35047.2.2.46.0`（`adUptime.0`）
  - 若返回类型为 `TimeTicks` 会自动换算 `ticks/100` → 秒

- `netsec_system_cpu_usage_percent{device_name="..."}`
  - CPU 使用率（%）
  - OID：`.1.3.6.1.4.1.35047.1.3.0`（`sfSysCpuCostRate.0`）

- `netsec_system_memory_usage_percent{device_name="..."}`
  - 内存使用率（%）
  - OID：`.1.3.6.1.4.1.35047.2.2.19.0`（`adMemCostRate.0`）

- `netsec_system_cpu_temperature_celsius{device_name="...",cpu_index="..."}`
  - CPU 温度（摄氏度）
  - 表 OID：`.1.3.6.1.4.1.35047.2.2.15.1.13`（`adCpuTemp`）

- `netsec_system_disk_usage_percent{device_name="...",disk_index="...",part_name="..."}`
  - 分区磁盘使用率（%）
  - 分区名称（标签）：`.1.3.6.1.4.1.35047.1.5.1.2`（`sfFilesystemName`）
  - 使用率（值，设备返回为字符串时会转数字）：`.1.3.6.1.4.1.35047.1.5.1.6`（`sfDiskUsedPercent`）

### 风扇与电源（SNMP 表）

- `netsec_system_fan_status{device_name="...",fan_index="...",fan_name="..."}`
  - 风扇状态（设备原始值）：`1=正常转速`，`2=较高转速`，`3=特高转速`
  - 名称（标签）：`.1.3.6.1.4.1.35047.1.14.1.2`（`sfFanName`）
  - 状态（值）：`.1.3.6.1.4.1.35047.1.14.1.4`（`sfFanState`）

- `netsec_system_fan_speed_rpm{device_name="...",fan_index="...",fan_name="..."}`
  - 风扇转速（RPM）
  - OID：`.1.3.6.1.4.1.35047.1.14.1.3`（`sfFanSpeed`）

- `netsec_system_power_status{device_name="...",power_index="...",power_name="..."}`
  - 电源状态（已做 0/1 映射）
    - 设备值 `2=正常` → 指标值 `1`
    - 设备值 `1=不正常` → 指标值 `0`
  - 名称（标签）：`.1.3.6.1.4.1.35047.1.15.1.2`（`sfPowerName`）
  - 状态（值）：`.1.3.6.1.4.1.35047.1.15.1.3`（`sfPowerState`）

### 会话与对象数量（SNMP）

- `netsec_session_active_current{device_name="..."}`
  - 并发连接数
  - OID：`.1.3.6.1.4.1.35047.2.2.1.0`（`adConns.0`）

- `netsec_sessions_new_per_second{device_name="..."}`
  - 新建连接数
  - OID：`adNewConns.0`（你提供的 OID 与 `adConns.0` 相同，后续提供正确 OID 后会修正）

- `netsec_vs_session_active_current{device_name="..."}`
  - 所有虚拟服务并发连接数
  - OID：`.1.3.6.1.4.1.35047.2.2.3.0`（`adVsConns.0`）

- `netsec_vs_sessions_new_per_second{device_name="..."}`
  - 所有虚拟服务新建连接数
  - OID：`.1.3.6.1.4.1.35047.2.2.4.0`（`adVsNewConns.0`）

- `netsec_vs_total{device_name="..."}`
  - 虚拟服务数量
  - OID：`.1.3.6.1.4.1.35047.2.2.22.0`（`adVsNumber.0`）

- `netsec_pool_total{device_name="..."}`
  - 节点池数量
  - OID：`.1.3.6.1.4.1.35047.2.2.23.0`（`adPoolNumber.0`）

- `netsec_node_total{device_name="..."}`
  - 节点数量
  - OID：`.1.3.6.1.4.1.35047.2.2.24.0`（`adNodeNumber.0`）

### 链路与接口（SNMP）

- `netsec_interface_send_bits{name="ALL",device_name="..."}`
  - 所有链路上行流量，单位 `kbps` 已换算为 `bps`
  - OID：`.1.3.6.1.4.1.35047.2.2.5.0`（`adUplinkThroughput.0`）

- `netsec_interface_recv_bits{name="ALL",device_name="..."}`
  - 所有链路下行流量，单位 `kbps` 已换算为 `bps`
  - OID：`.1.3.6.1.4.1.35047.2.2.6.0`（`adDownlinkThroughput.0`）

- `netsec_link_total{device_name="..."}`
  - 设备链路个数
  - OID：`.1.3.6.1.4.1.35047.2.2.42.0`（`adLinkNumber.0`）

链路表 `adLinkTable`（索引 `link_index`）：

- `netsec_link_type{device_name="...",link_index="...",link_name="...",if_name="...",link_descr="..."}`
  - OID：`.1.3.6.1.4.1.35047.2.2.41.1.3`（`adLinkType`）
- `netsec_link_oper_state{...}`
  - 状态：`0=离线`，`1=正常`，`2=繁忙`
  - OID：`.1.3.6.1.4.1.35047.2.2.41.1.5`（`adLinkStatus`）
- `netsec_link_traffic_in_bps{...}`
  - OID：`.1.3.6.1.4.1.35047.2.2.41.1.6`（`adLinkBitIn`）
- `netsec_link_traffic_out_bps{...}`
  - OID：`.1.3.6.1.4.1.35047.2.2.41.1.7`（`adLinkBitOut`）

接口速率表 `adIfTable`（索引 `if_index`）：

- `netsec_interface_speed_mbps{device_name="...",if_index="...",if_name="...",description="",zone="",mac="",ip_addr=""}`
  - OID：`.1.3.6.1.4.1.35047.2.2.7.1.3`（`adIfSpeed`）

接口统计表 `adInterfaceTable`（索引 `if_index`）：

- `netsec_interface_traffic_in_bits_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.3`（`adInterfaceBitIn`）
- `netsec_interface_traffic_out_bits_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.4`（`adInterfaceBitOut`）
- `netsec_interface_traffic_in_packets_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.5`（`adInterfacePacketIn`）
- `netsec_interface_traffic_out_packets_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.6`（`adInterfacePacketOut`）
- `netsec_interface_traffic_in_errors_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.7`（`adInterfaceErrorIn`）
- `netsec_interface_traffic_out_errors_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.8`（`adInterfaceErrorOut`）
- `netsec_interface_traffic_in_drops_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.9`（`adInterfaceDropIn`）
- `netsec_interface_traffic_out_drops_total{...}`：`.1.3.6.1.4.1.35047.2.2.43.1.10`（`adInterfaceDropOut`）

