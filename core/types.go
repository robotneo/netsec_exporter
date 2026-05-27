package core

type Device struct {
	Name   string `yaml:"name"`
	Host   string `yaml:"host"`
	Token  string `yaml:"token"`
	Vendor string `yaml:"vendor"`
	Type   string `yaml:"type"`
}

type Metric struct {
	Name   string
	Value  float64
	Labels map[string]string
}

type Job struct {
	Device Device
}
