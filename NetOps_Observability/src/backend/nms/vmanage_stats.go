package nms

import (
	"bytes"
	"encoding/json"
)

// vmanage_stats.go — vManage application-route statistics transformer. This is
// the METRIC half of the SD-WAN story (§3.1): per-tunnel latency / jitter /
// loss / QoE that ride VictoriaMetrics and can corroborate STAMP probes on the
// same path. Separate from the alarms transformer (different endpoint,
// different class).

// VManageStatsTransformer normalizes a vManage approute statistics response
// into controller_metric samples.
type VManageStatsTransformer struct{}

func (VManageStatsTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	var resp struct {
		Data []struct {
			VDevice     string  `json:"vdevice_name"`
			LocalIP     string  `json:"local_system_ip"`
			RemoteIP    string  `json:"remote_system_ip"`
			LocalColor  string  `json:"local_color"`
			RemoteColor string  `json:"remote_color"`
			SiteID      string  `json:"site_id"`
			Name        string  `json:"name"`
			Latency     float64 `json:"latency"`
			Jitter      float64 `json:"jitter"`
			Loss        float64 `json:"loss_percentage"`
			QoE         float64 `json:"vqoe_score"`
			EntryTime   int64   `json:"entry_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return Batch{}, err
	}
	var b Batch
	for _, s := range resp.Data {
		ts := msToTime(s.EntryTime)
		tags := map[string]string{
			"tenant_id": tenant, "integration_id": integrationID, "source_system": "vmanage",
			"device": s.VDevice, "site": s.SiteID, "tunnel": s.Name,
			"transport":   s.LocalColor + "-" + s.RemoteColor,
			"local_color": s.LocalColor, "remote_color": s.RemoteColor,
		}
		mk := func(name string, v float64, unit string) ControllerMetric {
			return ControllerMetric{
				TenantID: tenant, IntegrationID: integrationID, SourceSystem: "vmanage",
				Name: name, Value: v, Unit: unit, Time: ts, Tags: tags,
			}
		}
		b.Metrics = append(b.Metrics,
			mk("controller_metric_tunnel_latency_ms", s.Latency, "ms"),
			mk("controller_metric_tunnel_jitter_ms", s.Jitter, "ms"),
			mk("controller_metric_tunnel_loss_pct", s.Loss, "percent"),
			mk("controller_metric_tunnel_qoe", s.QoE, "score"),
		)
	}
	return b, nil
}

// VManageAutoTransformer is the connector-level transformer: it routes each
// polled payload to the stats or alarms transformer BY SHAPE — approute rows
// carry vqoe_score / loss_percentage keys an alarm never does. RunPollSession drives
// every stream through one Transformer seam, so without this the statistics
// stream would fall into the alarms parser and the metric lane would stay
// silently empty.
type VManageAutoTransformer struct{}

func (VManageAutoTransformer) Transform(tenant, integrationID string, raw []byte) (Batch, error) {
	if bytes.Contains(raw, []byte(`"vqoe_score"`)) || bytes.Contains(raw, []byte(`"loss_percentage"`)) {
		return VManageStatsTransformer{}.Transform(tenant, integrationID, raw)
	}
	return VManageTransformer{}.Transform(tenant, integrationID, raw)
}
