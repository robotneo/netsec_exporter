package hci

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"netsec_exporter/collectors/sangfor/client"
	"netsec_exporter/core"
)

type storageItem struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	Status         string  `json:"status"`
	StorageTagID   string  `json:"storage_tag_id"`
	AZID           string  `json:"az_id"`
	TotalMB        float64 `json:"total_mb"`
	UsedMB         float64 `json:"used_mb"`
	Ratio          float64 `json:"ratio"`
	ReadByteps     float64 `json:"read_byteps"`
	WriteByteps    float64 `json:"write_byteps"`
	MaxReadByteps  float64 `json:"max_read_byteps"`
	MaxWriteByteps float64 `json:"max_write_byteps"`
}

func CollectStorageMetrics(c *client.HCIClient, sess client.HCISession, dev core.Device) ([]core.Metric, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.HTTPClient.Timeout)
	defer cancel()

	storages, err := listStorages(ctx, c, sess)
	if err != nil {
		return nil, err
	}

	base := map[string]string{
		"device_name": dev.Name,
		"vendor":      dev.Vendor,
		"role":        dev.Type,
	}

	out := []core.Metric{
		{Name: "netsec_hci_storage_total", Value: float64(len(storages)), Labels: base},
	}

	for _, st := range storages {
		labels := cloneLabels(base)
		labels["storage_id"] = st.ID
		labels["storage_name"] = st.Name
		if strings.TrimSpace(st.AZID) != "" {
			labels["az_id"] = st.AZID
		}
		if strings.TrimSpace(st.Type) != "" {
			labels["storage_type"] = st.Type
		}
		if strings.TrimSpace(st.Status) != "" {
			labels["status"] = st.Status
		}
		if strings.TrimSpace(st.StorageTagID) != "" {
			labels["storage_tag_id"] = st.StorageTagID
		}

		out = append(out,
			core.Metric{Name: "netsec_hci_storage_total_bytes", Value: st.TotalMB * 1024 * 1024, Labels: labels},
			core.Metric{Name: "netsec_hci_storage_used_bytes", Value: st.UsedMB * 1024 * 1024, Labels: labels},
			core.Metric{Name: "netsec_hci_storage_usage_ratio", Value: st.Ratio, Labels: labels},
			core.Metric{Name: "netsec_hci_storage_read_bytes_per_second", Value: st.ReadByteps, Labels: labels},
			core.Metric{Name: "netsec_hci_storage_write_bytes_per_second", Value: st.WriteByteps, Labels: labels},
			core.Metric{Name: "netsec_hci_storage_max_read_bytes_per_second", Value: st.MaxReadByteps, Labels: labels},
			core.Metric{Name: "netsec_hci_storage_max_write_bytes_per_second", Value: st.MaxWriteByteps, Labels: labels},
		)
	}

	return out, nil
}

func listStorages(ctx context.Context, c *client.HCIClient, sess client.HCISession) ([]storageItem, error) {
	raw, err := doList(ctx, c, sess, "/janus/20180725/storages", "/janus/20190725/storages")
	if err != nil {
		return nil, err
	}

	var storages []storageItem
	if err := json.Unmarshal(raw, &storages); err == nil {
		return storages, nil
	}

	var wrapped struct {
		Message string        `json:"message"`
		Code    int           `json:"code"`
		Data    []storageItem `json:"data"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.Code != 0 {
		return nil, fmt.Errorf("storage list failed: code=%d message=%s", wrapped.Code, wrapped.Message)
	}
	return wrapped.Data, nil
}
