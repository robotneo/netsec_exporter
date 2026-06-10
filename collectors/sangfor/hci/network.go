package hci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

type vpcItem struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	AZID      string  `json:"az_id"`
	ProjectID string  `json:"project_id"`
	Status    string  `json:"status"`
	Shared    float64 `json:"shared"`
}

type subnetItem struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	AZID      string  `json:"az_id"`
	VPCID     string  `json:"vpc_id"`
	ProjectID string  `json:"project_id"`
	Status    string  `json:"status"`
	IsVisible float64 `json:"is_visible"`
}

type floatingIPPoolItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type floatingIPBandwidth struct {
	QosUplink   float64 `json:"qos_uplink"`
	QosDownlink float64 `json:"qos_downlink"`
}

type floatingIPBindingInfo struct {
	AZID  string `json:"az_id"`
	VPCID string `json:"vpc_id"`
}

type floatingIPItem struct {
	ID          string                 `json:"id"`
	ProjectID   string                 `json:"project_id"`
	FloatingIP  string                 `json:"floating_ip"`
	Bandwidth   floatingIPBandwidth    `json:"bandwidth"`
	BindingInfo *floatingIPBindingInfo `json:"binding_info"`
}

func CollectNetworkMetrics(c *client.HCIClient, sess client.HCISession, dev core.Device) ([]core.Metric, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
	defer cancel()

	vpcs, err := listVPCs(ctx, c, sess)
	if err != nil {
		return nil, err
	}
	subnets, err := listSubnets(ctx, c, sess)
	if err != nil {
		return nil, err
	}
	pools, err := listFloatingIPPools(ctx, c, sess)
	if err != nil {
		return nil, err
	}
	fips, err := listFloatingIPs(ctx, c, sess)
	if err != nil {
		return nil, err
	}

	base := map[string]string{
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"type":        dev.Type,
	}

	visibleSubnets := 0.0
	for _, s := range subnets {
		if s.IsVisible == 1 {
			visibleSubnets++
		}
	}

	out := []core.Metric{
		{Name: "netsec_hci_vpc_total", Value: float64(len(vpcs)), Labels: base},
		{Name: "netsec_hci_subnet_total", Value: float64(len(subnets)), Labels: base},
		{Name: "netsec_hci_subnet_visible_total", Value: visibleSubnets, Labels: base},
		{Name: "netsec_hci_floatingippool_total", Value: float64(len(pools)), Labels: base},
		{Name: "netsec_hci_floatingip_total", Value: float64(len(fips)), Labels: base},
	}

	for _, f := range fips {
		labels := cloneLabels(base)
		labels["floatingip_id"] = f.ID
		if strings.TrimSpace(f.ProjectID) != "" {
			labels["project_id"] = f.ProjectID
		}
		if strings.TrimSpace(f.FloatingIP) != "" {
			labels["floating_ip"] = f.FloatingIP
		}
		if f.BindingInfo != nil {
			if strings.TrimSpace(f.BindingInfo.AZID) != "" {
				labels["az_id"] = f.BindingInfo.AZID
			}
			if strings.TrimSpace(f.BindingInfo.VPCID) != "" {
				labels["vpc_id"] = f.BindingInfo.VPCID
			}
		}

		out = append(out,
			core.Metric{Name: "netsec_hci_floatingip_qos_uplink_bits_per_second", Value: f.Bandwidth.QosUplink * 1000, Labels: labels},
			core.Metric{Name: "netsec_hci_floatingip_qos_downlink_bits_per_second", Value: f.Bandwidth.QosDownlink * 1000, Labels: labels},
		)
	}

	return out, nil
}

func listVPCs(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]vpcItem, error) {
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/vpcs", nil, &raw); err != nil {
		return nil, err
	}

	var vpcs []vpcItem
	if err := json.Unmarshal(raw, &vpcs); err == nil {
		return vpcs, nil
	}

	var wrapped struct {
		Message string    `json:"message"`
		Code    int       `json:"code"`
		Data    []vpcItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("vpc list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}

func listSubnets(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]subnetItem, error) {
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/subnets", nil, &raw); err != nil {
		return nil, err
	}

	var subnets []subnetItem
	if err := json.Unmarshal(raw, &subnets); err == nil {
		return subnets, nil
	}

	var wrapped struct {
		Message string       `json:"message"`
		Code    int          `json:"code"`
		Data    []subnetItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("subnet list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}

func listFloatingIPPools(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]floatingIPPoolItem, error) {
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/floatingippools", nil, &raw); err != nil {
		return nil, err
	}

	var pools []floatingIPPoolItem
	if err := json.Unmarshal(raw, &pools); err == nil {
		return pools, nil
	}

	var wrapped struct {
		Message string               `json:"message"`
		Code    int                  `json:"code"`
		Data    []floatingIPPoolItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("floatingip pool list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}

func listFloatingIPs(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]floatingIPItem, error) {
	var raw json.RawMessage
	if err := c.DoJSON(ctx, sess, "GET", "/janus/20180725/floatingips", nil, &raw); err != nil {
		return nil, err
	}

	var fips []floatingIPItem
	if err := json.Unmarshal(raw, &fips); err == nil {
		return fips, nil
	}

	var wrapped struct {
		Message string           `json:"message"`
		Code    int              `json:"code"`
		Data    []floatingIPItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("floatingip list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}
