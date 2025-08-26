package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/your-org/kube-net-probe/pkg/collector"
)

// MetricType defines the type of Prometheus metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"   // Monotonically increasing values
	MetricTypeGauge     MetricType = "gauge"     // Values that can go up or down
	MetricTypeHistogram MetricType = "histogram" // Distribution of observations
	MetricTypeSummary   MetricType = "summary"   // Summary statistics
)

// Metric represents a single Prometheus-compatible metric
// Contains all necessary information for metric export
type Metric struct {
	Name      string            // Metric name (e.g., netprobe_tc_packets_total)
	Type      MetricType        // Prometheus metric type
	Help      string            // Human-readable description
	Labels    map[string]string // Key-value labels for metric dimensions
	Value     float64           // Numeric metric value
	Timestamp time.Time         // Collection timestamp
}

// String formats the metric in Prometheus exposition format
// Returns the metric line with labels and value
func (m *Metric) String() string {
	var labelPairs []string
	
	// Sort labels by key name for consistent output
	var keys []string
	for k := range m.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	
	// Build label string in key="value" format
	for _, k := range keys {
		labelPairs = append(labelPairs, fmt.Sprintf(`%s="%s"`, k, m.Labels[k]))
	}
	
	labelString := ""
	if len(labelPairs) > 0 {
		labelString = "{" + strings.Join(labelPairs, ",") + "}"
	}
	
	// 根据是否有时间戳决定格式
	if m.Timestamp.IsZero() {
		return fmt.Sprintf("%s%s %.6f", m.Name, labelString, m.Value)
	}
	
	// Format: metric_name{labels} value timestamp_ms
	return fmt.Sprintf("%s%s %.6f %d", m.Name, labelString, m.Value, m.Timestamp.UnixMilli())
}

// NetworkMetrics manages collection and formatting of network monitoring metrics
// Thread-safe collector that converts interface statistics to Prometheus metrics
type NetworkMetrics struct {
	mutex           sync.RWMutex    // Protects concurrent access to metrics
	metrics         []Metric        // Current metric collection
	lastCollection  time.Time       // Timestamp of last metrics update
	collectionCount uint64          // Total number of collection cycles
}

// NewNetworkMetrics creates a new network metrics collector
// Initializes empty metrics collection ready for use
func NewNetworkMetrics() *NetworkMetrics {
	return &NetworkMetrics{
		metrics: make([]Metric, 0),
	}
}

// Update refreshes all metrics with current interface statistics
// Thread-safe method that replaces existing metrics with fresh data
func (nm *NetworkMetrics) Update(stats []collector.InterfaceStats) {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	now := time.Now()
	nm.lastCollection = now
	nm.collectionCount++
	
	// Clear previous metrics to avoid stale data
	nm.metrics = nm.metrics[:0]
	
	// Add system-level metadata metrics
	nm.addMetaMetrics(now)
	
	// Generate metrics for each network interface
	for _, stat := range stats {
		nm.addInterfaceMetrics(stat, now)
	}
}

// addMetaMetrics generates system-level monitoring metadata
func (nm *NetworkMetrics) addMetaMetrics(now time.Time) {
	// 收集次数
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_collection_total",
		Type:      MetricTypeCounter,
		Help:      "Total number of metric collections performed",
		Value:     float64(nm.collectionCount),
		Timestamp: now,
	})
	
	// 最后收集时间
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_last_collection_timestamp_seconds",
		Type:      MetricTypeGauge,
		Help:      "Unix timestamp of the last collection",
		Value:     float64(now.Unix()),
		Timestamp: now,
	})
	
	// 当前时间（用于健康检查）
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_up",
		Type:      MetricTypeGauge,
		Help:      "Whether the netprobe exporter is up",
		Value:     1,
		Timestamp: now,
	})
}

// addInterfaceMetrics 为单个接口添加指标
func (nm *NetworkMetrics) addInterfaceMetrics(stat collector.InterfaceStats, now time.Time) {
	labels := map[string]string{
		"interface": stat.InterfaceName,
		"ifindex":   fmt.Sprintf("%d", stat.InterfaceIndex),
	}
	
	// 入站包数指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_packets_total",
		Type:      MetricTypeCounter,
		Help:      "Total number of packets processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "ingress"}),
		Value:     float64(stat.IngressPackets),
		Timestamp: now,
	})
	
	// 出站包数指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_packets_total",
		Type:      MetricTypeCounter,
		Help:      "Total number of packets processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "egress"}),
		Value:     float64(stat.EgressPackets),
		Timestamp: now,
	})
	
	// 入站字节数指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_bytes_total",
		Type:      MetricTypeCounter,
		Help:      "Total number of bytes processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "ingress"}),
		Value:     float64(stat.IngressBytes),
		Timestamp: now,
	})
	
	// 出站字节数指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_bytes_total",
		Type:      MetricTypeCounter,
		Help:      "Total number of bytes processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "egress"}),
		Value:     float64(stat.EgressBytes),
		Timestamp: now,
	})
	
	// 入站包速率指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_packets_per_second",
		Type:      MetricTypeGauge,
		Help:      "Rate of packets per second processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "ingress"}),
		Value:     stat.IngressPacketsRate,
		Timestamp: now,
	})
	
	// 出站包速率指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_packets_per_second",
		Type:      MetricTypeGauge,
		Help:      "Rate of packets per second processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "egress"}),
		Value:     stat.EgressPacketsRate,
		Timestamp: now,
	})
	
	// 入站字节速率指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_bytes_per_second",
		Type:      MetricTypeGauge,
		Help:      "Rate of bytes per second processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "ingress"}),
		Value:     stat.IngressBytesRate,
		Timestamp: now,
	})
	
	// 出站字节速率指标
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_tc_bytes_per_second",
		Type:      MetricTypeGauge,
		Help:      "Rate of bytes per second processed by TC",
		Labels:    mergeLabels(labels, map[string]string{"direction": "egress"}),
		Value:     stat.EgressBytesRate,
		Timestamp: now,
	})
	
	// 接口活跃状态指标
	activeValue := 0.0
	if stat.HasActivity() {
		activeValue = 1.0
	}
	nm.metrics = append(nm.metrics, Metric{
		Name:      "netprobe_interface_active",
		Type:      MetricTypeGauge,
		Help:      "Whether the network interface is currently active (1 = active, 0 = inactive)",
		Labels:    labels,
		Value:     activeValue,
		Timestamp: now,
	})
}

// GetMetrics 获取所有指标
func (nm *NetworkMetrics) GetMetrics() []Metric {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	// 返回指标的副本
	result := make([]Metric, len(nm.metrics))
	copy(result, nm.metrics)
	return result
}

// GetPrometheusFormat 获取 Prometheus 格式的指标输出
func (nm *NetworkMetrics) GetPrometheusFormat() string {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	
	var output strings.Builder
	
	// 按指标名称分组
	metricGroups := make(map[string][]Metric)
	helpTexts := make(map[string]string)
	typeTexts := make(map[string]MetricType)
	
	for _, metric := range nm.metrics {
		metricGroups[metric.Name] = append(metricGroups[metric.Name], metric)
		helpTexts[metric.Name] = metric.Help
		typeTexts[metric.Name] = metric.Type
	}
	
	// 按指标名称排序
	var metricNames []string
	for name := range metricGroups {
		metricNames = append(metricNames, name)
	}
	sort.Strings(metricNames)
	
	// 输出每个指标组
	for _, name := range metricNames {
		metrics := metricGroups[name]
		
		// 输出 HELP 注释
		if help := helpTexts[name]; help != "" {
			output.WriteString(fmt.Sprintf("# HELP %s %s\n", name, help))
		}
		
		// 输出 TYPE 注释
		if metricType := typeTexts[name]; metricType != "" {
			output.WriteString(fmt.Sprintf("# TYPE %s %s\n", name, metricType))
		}
		
		// 输出指标值
		for _, metric := range metrics {
			output.WriteString(metric.String())
			output.WriteString("\n")
		}
		
		output.WriteString("\n")
	}
	
	return output.String()
}

// GetMetricCount 获取指标数量
func (nm *NetworkMetrics) GetMetricCount() int {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return len(nm.metrics)
}

// GetLastCollectionTime 获取最后收集时间
func (nm *NetworkMetrics) GetLastCollectionTime() time.Time {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return nm.lastCollection
}

// GetCollectionCount 获取收集次数
func (nm *NetworkMetrics) GetCollectionCount() uint64 {
	nm.mutex.RLock()
	defer nm.mutex.RUnlock()
	return nm.collectionCount
}

// mergeLabels 合并标签映射
func mergeLabels(base, additional map[string]string) map[string]string {
	result := make(map[string]string)
	
	// 复制基础标签
	for k, v := range base {
		result[k] = v
	}
	
	// 添加额外标签
	for k, v := range additional {
		result[k] = v
	}
	
	return result
}
