package firewall

import (
	"context"

	"netsec_exporter/collectors/qianxin/client"
	"netsec_exporter/core"
)

func fetchSystemResource(ctx context.Context, c *client.Client, sess client.Session, dev core.Device) (qianxinSystemResourceResponse, error) {
	req := []client.RESTRequest{
		{
			Head: client.RESTHead{
				Function:  "get_system_resource",
				Module:    "dashboard",
				PageIndex: 1,
				PageSize:  20,
			},
			Body: client.RESTBody{},
		},
	}

	var resp qianxinSystemResourceResponse
	if err := c.PostREST(ctx, dev, sess, req, &resp); err != nil {
		return qianxinSystemResourceResponse{}, err
	}
	if err := client.EnsureRESTOK("get_system_resource", resp.Head); err != nil {
		return qianxinSystemResourceResponse{}, err
	}
	return resp, nil
}

type qianxinSystemResourceResponse struct {
	Head client.RESTResponseHead `json:"head"`
	Data struct {
		Memery      qianxinSystemResourceMemory       `json:"memery"`
		MemoryCores []qianxinSystemResourceMemoryCore `json:"memory_cores"`
		CF          qianxinSystemResourceDisk         `json:"cf"`
		SSD         qianxinSystemResourceDisk         `json:"ssd"`
		CPU         []qianxinSystemResourceCPU        `json:"cpu"`
		Fan         []qianxinSystemResourceFan        `json:"fan"`
		Power       []qianxinSystemResourcePower      `json:"power"`
		PowerSupply qianxinSystemResourcePowerSupply  `json:"power_supply"`
	} `json:"data"`
}

type qianxinSystemResourceMemory struct {
	Useage float64 `json:"useage"`
	Total  float64 `json:"total"`
}

type qianxinSystemResourceMemoryCore struct {
	Name   string  `json:"name"`
	Free   float64 `json:"free"`
	Useage float64 `json:"useage"`
}

type qianxinSystemResourceDisk struct {
	Use    float64 `json:"use"`
	Total  float64 `json:"total"`
	Free   float64 `json:"free"`
	Useage float64 `json:"useage"`
}

type qianxinSystemResourceCPU struct {
	Name   string  `json:"name"`
	Useage float64 `json:"useage"`
	Temp   float64 `json:"temp"`
}

type qianxinSystemResourceFan struct {
	Name   string  `json:"name"`
	Speed  float64 `json:"speed"`
	Status string  `json:"status"`
	Flag   int     `json:"flag"`
}

type qianxinSystemResourcePower struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type qianxinSystemResourcePowerSupply struct {
	Capacity string `json:"capacity"`
	View     int    `json:"view"`
}
