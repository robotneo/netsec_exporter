package core

type Device struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	Token    string `yaml:"token"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Vendor   string `yaml:"vendor"`
	Type     string `yaml:"type"`
}

type Metric struct {
	Name   string
	Value  float64
	Labels map[string]string
}

type Job struct {
	Device Device
}

func NormalizeCommonLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return labels
	}

	if v, ok := labels["device"]; ok {
		if _, exists := labels["device_name"]; !exists {
			labels["device_name"] = v
		}
		delete(labels, "device")
	}

	if v, ok := labels["host"]; ok {
		if _, exists := labels["instance"]; !exists {
			labels["instance"] = v
		}
		delete(labels, "host")
	}

	if v, ok := labels["type"]; ok {
		if _, exists := labels["role"]; !exists {
			labels["role"] = v
		}
		delete(labels, "type")
	}

	return labels
}
