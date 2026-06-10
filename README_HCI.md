# 深信服 HCI（SCP / Janus）采集说明

本项目通过 `vendor=sangfor&type=hci` 采集深信服 HCI 的指标，并以 Prometheus `/probe` 多目标模式输出。

## 1. 认证方式

支持两种方式（二选一）：

- Token：通过 `auth_file` 直接提供 `token`（推荐，避免把用户名/密码暴露给 Prometheus 配置）
- 用户名密码：通过 `auth_file` 提供 `username/password`，exporter 会按 OpenAPI 流程完成登录并缓存 token（token 接近过期会自动刷新）

## 2. /probe 参数（Prometheus 侧）

必须参数：

- `target`: HCI 管理地址（示例：`10.0.0.10`）
- `vendor`: `sangfor`
- `type`: `hci`
- `auth`: `auth_file` 中定义的认证条目 ID

示例：

```
/probe?target=10.0.0.10&vendor=sangfor&type=hci&auth=hci-prod
```

## 3. 指标与标签

所有指标默认带基础标签：

- `device_name`：在设备定义中配置的名称
- `vendor`：`sangfor`
- `type`：`hci`

部分指标会附加资源维度标签（例如 `az_id/host_id/vm_id/storage_id` 等）。以下仅列出当前 exporter 已实现的指标名称（按模块分组）。

### 3.1 平台概况（overview）

- `netsec_hci_overview_hosts_total`
- `netsec_hci_overview_hosts_online`
- `netsec_hci_overview_hosts_offline`
- `netsec_hci_overview_hosts_alarm`
- `netsec_hci_overview_servers_total`
- `netsec_hci_overview_servers_running`
- `netsec_hci_overview_servers_offline`
- `netsec_hci_overview_servers_alarm`
- `netsec_hci_overview_servers_error`
- `netsec_hci_overview_az_total`
- `netsec_hci_overview_az_online`
- `netsec_hci_overview_az_offline`
- `netsec_hci_overview_az_alarm`
- `netsec_hci_overview_nfv_total`
- `netsec_hci_overview_nfv_running`
- `netsec_hci_overview_nfv_offline`
- `netsec_hci_overview_nfv_error`
- `netsec_hci_overview_virtual_resource_limit_bytes`
- `netsec_hci_overview_virtual_resource_total_bytes`
- `netsec_hci_overview_virtual_resource_allocated_bytes`
- `netsec_hci_overview_virtual_resource_occupied_bytes`
- `netsec_hci_overview_virtual_resource_limit_hz`
- `netsec_hci_overview_virtual_resource_total_hz`
- `netsec_hci_overview_virtual_resource_allocated_hz`
- `netsec_hci_overview_virtual_resource_occupied_hz`
- `netsec_hci_overview_physical_resource_total_bytes`
- `netsec_hci_overview_physical_resource_used_bytes`
- `netsec_hci_overview_physical_resource_total_hz`
- `netsec_hci_overview_physical_resource_used_hz`

资源指标附加标签：

- `resource_name`

### 3.2 资源池（AZ）与物理主机（host）

资源池信息：

- `netsec_hci_az_info`（附加 `az_id/az_name`）
- `netsec_hci_az_virtual_resource_limit_bytes`
- `netsec_hci_az_virtual_resource_total_bytes`
- `netsec_hci_az_virtual_resource_allocated_bytes`
- `netsec_hci_az_virtual_resource_occupied_bytes`
- `netsec_hci_az_virtual_resource_limit_hz`
- `netsec_hci_az_virtual_resource_total_hz`
- `netsec_hci_az_virtual_resource_allocated_hz`
- `netsec_hci_az_virtual_resource_occupied_hz`
- `netsec_hci_az_physical_resource_total_bytes`
- `netsec_hci_az_physical_resource_used_bytes`
- `netsec_hci_az_physical_resource_total_hz`
- `netsec_hci_az_physical_resource_used_hz`

资源池资源指标附加标签：

- `az_id`
- `az_name`
- `resource_name`

物理主机指标：

- `netsec_hci_host_alarm_count`
- `netsec_hci_host_cpu_usage_ratio`
- `netsec_hci_host_cpu_total_mhz`
- `netsec_hci_host_cpu_used_mhz`
- `netsec_hci_host_cpu_core_count`
- `netsec_hci_host_memory_usage_ratio`
- `netsec_hci_host_memory_total_bytes`
- `netsec_hci_host_memory_used_bytes`
- `netsec_hci_host_gpu_usage_ratio`
- `netsec_hci_host_gpu_total_count`
- `netsec_hci_host_gpu_used_count`
- `netsec_hci_host_gpu_memory_usage_ratio`
- `netsec_hci_host_gpu_memory_total_bytes`
- `netsec_hci_host_gpu_memory_used_bytes`

物理主机指标附加标签：

- `az_id`
- `az_name`
- `host_id`
- `host_name`
- `host_ip`

### 3.3 虚拟机（VM / server）

计数：

- `netsec_hci_vm_total`

单 VM 指标：

- `netsec_hci_vm_uptime_seconds`
- `netsec_hci_vm_alarm`
- `netsec_hci_vm_cpu_usage_ratio`
- `netsec_hci_vm_cpu_total_mhz`
- `netsec_hci_vm_cpu_used_mhz`
- `netsec_hci_vm_memory_usage_ratio`
- `netsec_hci_vm_memory_total_bytes`
- `netsec_hci_vm_memory_used_bytes`
- `netsec_hci_vm_storage_usage_ratio`
- `netsec_hci_vm_storage_total_bytes`
- `netsec_hci_vm_storage_used_bytes`
- `netsec_hci_vm_storage_file_size_bytes`
- `netsec_hci_vm_io_read_bytes_per_second`
- `netsec_hci_vm_io_write_bytes_per_second`
- `netsec_hci_vm_io_read_iops`
- `netsec_hci_vm_io_write_iops`
- `netsec_hci_vm_network_read_bits_per_second`
- `netsec_hci_vm_network_write_bits_per_second`

VM 指标附加标签（低基数建议仅保留必要项）：

- `vm_id`
- `vm_name`
- `az_id`（可选）
- `az_name`（可选）
- `host_id`（可选）
- `host_name`（可选）
- `project_id`（可选）
- `project_name`（可选）

### 3.4 存储（storage）

计数：

- `netsec_hci_storage_total`

单存储指标：

- `netsec_hci_storage_total_bytes`
- `netsec_hci_storage_used_bytes`
- `netsec_hci_storage_usage_ratio`
- `netsec_hci_storage_read_bytes_per_second`
- `netsec_hci_storage_write_bytes_per_second`
- `netsec_hci_storage_max_read_bytes_per_second`
- `netsec_hci_storage_max_write_bytes_per_second`

存储指标附加标签：

- `storage_id`
- `storage_name`
- `az_id`（可选）
- `storage_type`（可选）
- `status`（可选）
- `storage_tag_id`（可选）

### 3.5 网络（VPC / 子网 / 浮动 IP）

计数：

- `netsec_hci_vpc_total`
- `netsec_hci_subnet_total`
- `netsec_hci_subnet_visible_total`
- `netsec_hci_floatingippool_total`
- `netsec_hci_floatingip_total`

浮动 IP QoS：

- `netsec_hci_floatingip_qos_uplink_bits_per_second`
- `netsec_hci_floatingip_qos_downlink_bits_per_second`

浮动 IP QoS 指标附加标签：

- `floatingip_id`
- `project_id`（可选）
- `floating_ip`（可选）
- `az_id`（可选）
- `vpc_id`（可选）
