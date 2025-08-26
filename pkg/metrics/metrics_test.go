package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/your-org/kube-net-probe/pkg/collector"
)

// TestMetric 测试 Metric 结构
func TestMetric(t *testing.T) {
	metric := Metric{
		Name: "test_metric",
		Type: MetricTypeGauge,
		Help: "A test metric",
		Labels: map[string]string{
			"interface": "eth0",
			"direction": "ingress",
		},
		Value:     123.456,
		Timestamp: time.Unix(1609459200, 0), // 2021-01-01 00:00:00 UTC
	}

	// 测试 String 方法
	result := metric.String()
	expected := `test_metric{direction="ingress",interface="eth0"} 123.456000 1609459200000`
	
	if result != expected {
		t.Errorf("Metric.String() = %s, expected %s", result, expected)
	}
}

// TestMetricWithoutTimestamp 测试没有时间戳的指标
func TestMetricWithoutTimestamp(t *testing.T) {
	metric := Metric{
		Name: "test_metric",
		Labels: map[string]string{
			"key": "value",
		},
		Value: 42.0,
	}

	result := metric.String()
	expected := `test_metric{key="value"} 42.000000`
	
	if result != expected {
		t.Errorf("Metric.String() = %s, expected %s", result, expected)
	}
}

// TestMetricWithoutLabels 测试没有标签的指标
func TestMetricWithoutLabels(t *testing.T) {
	metric := Metric{
		Name:  "simple_metric",
		Value: 1.0,
	}

	result := metric.String()
	expected := `simple_metric 1.000000`
	
	if result != expected {
		t.Errorf("Metric.String() = %s, expected %s", result, expected)
	}
}

// TestNetworkMetricsUpdate 测试网络指标更新
func TestNetworkMetricsUpdate(t *testing.T) {
	nm := NewNetworkMetrics()
	
	stats := []collector.InterfaceStats{
		{
			InterfaceName:      "eth0",
			InterfaceIndex:     1,
			IngressPackets:     1000,
			IngressBytes:       64000,
			EgressPackets:      800,
			EgressBytes:        51200,
			IngressPacketsRate: 10.0,
			IngressBytesRate:   640.0,
			EgressPacketsRate:  8.0,
			EgressBytesRate:    512.0,
		},
	}
	
	// 更新指标
	nm.Update(stats)
	
	// 检查指标数量
	metrics := nm.GetMetrics()
	if len(metrics) == 0 {
		t.Error("Expected metrics to be generated")
	}
	
	// 检查收集计数
	if nm.GetCollectionCount() != 1 {
		t.Errorf("Expected collection count to be 1, got %d", nm.GetCollectionCount())
	}
	
	// 检查最后收集时间
	if nm.GetLastCollectionTime().IsZero() {
		t.Error("Expected last collection time to be set")
	}
}

// TestNetworkMetricsPrometheusFormat 测试 Prometheus 格式输出
func TestNetworkMetricsPrometheusFormat(t *testing.T) {
	nm := NewNetworkMetrics()
	
	stats := []collector.InterfaceStats{
		{
			InterfaceName:  "eth0",
			InterfaceIndex: 1,
			IngressPackets: 1000,
			IngressBytes:   64000,
		},
	}
	
	nm.Update(stats)
	
	output := nm.GetPrometheusFormat()
	
	// 检查输出不为空
	if output == "" {
		t.Error("Expected non-empty Prometheus format output")
	}
	
	// 检查是否包含期望的指标
	expectedMetrics := []string{
		"netprobe_tc_packets_total",
		"netprobe_tc_bytes_total",
		"netprobe_up",
	}
	
	for _, metric := range expectedMetrics {
		if !strings.Contains(output, metric) {
			t.Errorf("Expected output to contain metric %s", metric)
		}
	}
	
	// 检查是否包含 HELP 和 TYPE 注释
	if !strings.Contains(output, "# HELP") {
		t.Error("Expected output to contain HELP comments")
	}
	
	if !strings.Contains(output, "# TYPE") {
		t.Error("Expected output to contain TYPE comments")
	}
}

// TestNetworkMetricsMultipleInterfaces 测试多接口指标
func TestNetworkMetricsMultipleInterfaces(t *testing.T) {
	nm := NewNetworkMetrics()
	
	stats := []collector.InterfaceStats{
		{
			InterfaceName:  "eth0",
			InterfaceIndex: 1,
			IngressPackets: 1000,
		},
		{
			InterfaceName:  "wlan0",
			InterfaceIndex: 2,
			EgressPackets:  800,
		},
	}
	
	nm.Update(stats)
	
	output := nm.GetPrometheusFormat()
	
	// 检查是否包含两个接口的指标
	if !strings.Contains(output, `interface="eth0"`) {
		t.Error("Expected output to contain eth0 interface")
	}
	
	if !strings.Contains(output, `interface="wlan0"`) {
		t.Error("Expected output to contain wlan0 interface")
	}
}

// TestMetricLabels 测试指标标签
func TestMetricLabels(t *testing.T) {
	nm := NewNetworkMetrics()
	
	stats := []collector.InterfaceStats{
		{
			InterfaceName:  "eth0",
			InterfaceIndex: 1,
			IngressPackets: 1000,
		},
	}
	
	nm.Update(stats)
	
	metrics := nm.GetMetrics()
	
	// 查找包指标
	var packetMetric *Metric
	for _, metric := range metrics {
		if metric.Name == "netprobe_tc_packets_total" {
			packetMetric = &metric
			break
		}
	}
	
	if packetMetric == nil {
		t.Fatal("Expected to find packet metric")
	}
	
	// 检查标签
	expectedLabels := map[string]string{
		"interface": "eth0",
		"ifindex":   "1",
		"direction": "ingress",
	}
	
	for key, expectedValue := range expectedLabels {
		if actualValue, exists := packetMetric.Labels[key]; !exists || actualValue != expectedValue {
			t.Errorf("Expected label %s=%s, got %s=%s", key, expectedValue, key, actualValue)
		}
	}
}

// TestServerConfig 测试服务器配置
func TestServerConfig(t *testing.T) {
	config := DefaultServerConfig()
	
	// 检查默认值
	if config.Port != 8081 {
		t.Errorf("Expected default port 8081, got %d", config.Port)
	}
	
	if config.Path != "/metrics" {
		t.Errorf("Expected default path /metrics, got %s", config.Path)
	}
	
	if config.ReadTimeout != 10*time.Second {
		t.Errorf("Expected default read timeout 10s, got %v", config.ReadTimeout)
	}
	
	if !config.EnableCORS {
		t.Error("Expected CORS to be enabled by default")
	}
}

// TestExporterConfig 测试导出器配置
func TestExporterConfig(t *testing.T) {
	config := DefaultExporterConfig()
	
	// 检查默认值
	if config.CollectInterval != 5*time.Second {
		t.Errorf("Expected default collect interval 5s, got %v", config.CollectInterval)
	}
	
	if config.ServerConfig == nil {
		t.Error("Expected server config to be set")
	}
	
	if config.LogLevel != "info" {
		t.Errorf("Expected default log level info, got %s", config.LogLevel)
	}
}

// TestMergeLabels 测试标签合并
func TestMergeLabels(t *testing.T) {
	base := map[string]string{
		"interface": "eth0",
		"ifindex":   "1",
	}
	
	additional := map[string]string{
		"direction": "ingress",
		"ifindex":   "2", // 应该覆盖基础标签
	}
	
	result := mergeLabels(base, additional)
	
	// 检查合并结果
	expected := map[string]string{
		"interface": "eth0",
		"ifindex":   "2",     // 应该被覆盖
		"direction": "ingress",
	}
	
	if len(result) != len(expected) {
		t.Errorf("Expected %d labels, got %d", len(expected), len(result))
	}
	
	for key, expectedValue := range expected {
		if actualValue, exists := result[key]; !exists || actualValue != expectedValue {
			t.Errorf("Expected label %s=%s, got %s=%s", key, expectedValue, key, actualValue)
		}
	}
}

// TestNetworkMetricsEmpty 测试空指标更新
func TestNetworkMetricsEmpty(t *testing.T) {
	nm := NewNetworkMetrics()
	
	// 更新空统计
	nm.Update([]collector.InterfaceStats{})
	
	// 应该仍然有元数据指标
	metrics := nm.GetMetrics()
	if len(metrics) == 0 {
		t.Error("Expected metadata metrics even with empty stats")
	}
	
	// 检查是否包含 up 指标
	hasUpMetric := false
	for _, metric := range metrics {
		if metric.Name == "netprobe_up" {
			hasUpMetric = true
			if metric.Value != 1.0 {
				t.Errorf("Expected up metric value 1.0, got %f", metric.Value)
			}
			break
		}
	}
	
	if !hasUpMetric {
		t.Error("Expected to find netprobe_up metric")
	}
}
