package client

import "netsec_exporter/core"

type Session struct {
	Token  string
	Cookie string
}

// Login 预留给后续网神防火墙登录/换取 token 或 cookie 的实现。
func (c *Client) Login(dev core.Device) (Session, error) {
	_ = c
	_ = dev
	return Session{}, nil
}
