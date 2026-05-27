package core

// Collector 定义所有网络设备采集插件的标准接口
type Collector interface {

	// Name 插件名称（必须唯一）
	Name() string

	// Collect 执行采集并返回统一指标
	Collect(dev Device) ([]Metric, error)

	// Supported 是否支持该设备（可选扩展）
	// 用于未来混合厂商自动匹配
	Supported(dev Device) bool
}
