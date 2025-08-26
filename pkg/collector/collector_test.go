package collector

import (
	"testing"
	"time"
)

// TestTCDirection 测试 TC 方向枚举
func TestTCDirection(t *testing.T) {
	tests := []struct {
		direction TCDirection
		expected  string
	}{
		{TCDirectionIngress, "ingress"},
		{TCDirectionEgress, "egress"},
		{TCDirection(999), "unknown"},
	}

	for _, test := range tests {
		result := test.direction.String()
		if result != test.expected {
			t.Errorf("TCDirection(%d).String() = %s, expected %s",
				test.direction, result, test.expected)
		}
	}
}

// TestTCStatType 测试 TC 统计类型枚举
func TestTCStatType(t *testing.T) {
	tests := []struct {
		statType TCStatType
		expected string
	}{
		{TCStatPackets, "packets"},
		{TCStatBytes, "bytes"},
		{TCStatType(999), "unknown"},
	}

	for _, test := range tests {
		result := test.statType.String()
		if result != test.expected {
			t.Errorf("TCStatType(%d).String() = %s, expected %s",
				test.statType, result, test.expected)
		}
	}
}

// TestInterfaceStats 测试接口统计方法
func TestInterfaceStats(t *testing.T) {
	stats := InterfaceStats{
		InterfaceName:      "eth0",
		InterfaceIndex:     1,
		IngressPackets:     1000,
		IngressBytes:       64000,
		EgressPackets:      800,
		EgressBytes:        51200,
		IngressPacketsRate: 10.5,
		IngressBytesRate:   672.0,
		EgressPacketsRate:  8.2,
		EgressBytesRate:    537.6,
		LastUpdated:        time.Now(),
	}

	// 测试 HasTraffic
	if !stats.HasTraffic() {
		t.Error("Expected HasTraffic() to return true")
	}

	// 测试 HasActivity
	if !stats.HasActivity() {
		t.Error("Expected HasActivity() to return true")
	}

	// 测试 TotalPackets
	expectedPackets := uint64(1800)
	if stats.TotalPackets() != expectedPackets {
		t.Errorf("TotalPackets() = %d, expected %d",
			stats.TotalPackets(), expectedPackets)
	}

	// 测试 TotalBytes
	expectedBytes := uint64(115200)
	if stats.TotalBytes() != expectedBytes {
		t.Errorf("TotalBytes() = %d, expected %d",
			stats.TotalBytes(), expectedBytes)
	}

	// 测试 TotalPacketsRate
	expectedPacketsRate := 18.7
	if abs(stats.TotalPacketsRate()-expectedPacketsRate) > 0.01 {
		t.Errorf("TotalPacketsRate() = %.2f, expected %.2f",
			stats.TotalPacketsRate(), expectedPacketsRate)
	}

	// 测试 TotalBytesRate
	expectedBytesRate := 1209.6
	if abs(stats.TotalBytesRate()-expectedBytesRate) > 0.01 {
		t.Errorf("TotalBytesRate() = %.2f, expected %.2f",
			stats.TotalBytesRate(), expectedBytesRate)
	}
}

// TestInterfaceStatsNoTraffic 测试无流量的接口统计
func TestInterfaceStatsNoTraffic(t *testing.T) {
	stats := InterfaceStats{
		InterfaceName:  "lo",
		InterfaceIndex: 2,
		LastUpdated:    time.Now(),
	}

	// 测试 HasTraffic
	if stats.HasTraffic() {
		t.Error("Expected HasTraffic() to return false for empty stats")
	}

	// 测试 HasActivity
	if stats.HasActivity() {
		t.Error("Expected HasActivity() to return false for empty stats")
	}

	// 测试总计
	if stats.TotalPackets() != 0 {
		t.Errorf("TotalPackets() = %d, expected 0", stats.TotalPackets())
	}

	if stats.TotalBytes() != 0 {
		t.Errorf("TotalBytes() = %d, expected 0", stats.TotalBytes())
	}
}

// TestFormatBytes 测试字节格式化
func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    uint64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{1073741824, "1.00 GB"},
		{1099511627776, "1.00 TB"},
	}

	for _, test := range tests {
		result := FormatBytes(test.bytes)
		if result != test.expected {
			t.Errorf("FormatBytes(%d) = %s, expected %s",
				test.bytes, result, test.expected)
		}
	}
}

// TestFormatRate 测试速率格式化
func TestFormatRate(t *testing.T) {
	tests := []struct {
		rate     float64
		unit     string
		expected string
	}{
		{10.5, "pkt", "10.50 pkt/s"},
		{1500.0, "pkt", "1.50 Kpkt/s"},
		{1500000.0, "B", "1.50 MB/s"},
		{2500000000.0, "B", "2.50 GB/s"},
	}

	for _, test := range tests {
		result := FormatRate(test.rate, test.unit)
		if result != test.expected {
			t.Errorf("FormatRate(%.2f, %s) = %s, expected %s",
				test.rate, test.unit, result, test.expected)
		}
	}
}

// TestSummarizeCollection 测试收集摘要
func TestSummarizeCollection(t *testing.T) {
	stats := []InterfaceStats{
		{
			InterfaceName:      "eth0",
			IngressPackets:     1000,
			IngressBytes:       64000,
			EgressPackets:      800,
			EgressBytes:        51200,
			IngressPacketsRate: 10.0,
			IngressBytesRate:   640.0,
			EgressPacketsRate:  8.0,
			EgressBytesRate:    512.0,
		},
		{
			InterfaceName:      "lo",
			IngressPackets:     100,
			IngressBytes:       6400,
			EgressPackets:      100,
			EgressBytes:        6400,
			IngressPacketsRate: 1.0,
			IngressBytesRate:   64.0,
			EgressPacketsRate:  1.0,
			EgressBytesRate:    64.0,
		},
		{
			InterfaceName: "wlan0",
			// 无流量接口
		},
	}

	summary := SummarizeCollection(stats, 2)

	// 检查总接口数
	if summary.TotalInterfaces != 3 {
		t.Errorf("TotalInterfaces = %d, expected 3", summary.TotalInterfaces)
	}

	// 检查活跃接口数
	if summary.ActiveInterfaces != 2 {
		t.Errorf("ActiveInterfaces = %d, expected 2", summary.ActiveInterfaces)
	}

	// 检查总包数
	expectedTotalPackets := uint64(2000)
	if summary.TotalPackets != expectedTotalPackets {
		t.Errorf("TotalPackets = %d, expected %d",
			summary.TotalPackets, expectedTotalPackets)
	}

	// 检查总字节数
	expectedTotalBytes := uint64(128000)
	if summary.TotalBytes != expectedTotalBytes {
		t.Errorf("TotalBytes = %d, expected %d",
			summary.TotalBytes, expectedTotalBytes)
	}

	// 检查 Top 接口数量
	if len(summary.TopInterfaces) != 2 {
		t.Errorf("TopInterfaces length = %d, expected 2", len(summary.TopInterfaces))
	}

	// 检查排序（eth0 应该排在第一位，因为它的总字节速率更高）
	if len(summary.TopInterfaces) > 0 && summary.TopInterfaces[0].InterfaceName != "eth0" {
		t.Errorf("First interface should be eth0, got %s",
			summary.TopInterfaces[0].InterfaceName)
	}
}

// TestFilterActiveInterfaces 测试活跃接口过滤
func TestFilterActiveInterfaces(t *testing.T) {
	stats := []InterfaceStats{
		{
			InterfaceName:      "eth0",
			IngressPacketsRate: 10.0, // 活跃
		},
		{
			InterfaceName:      "lo",
			IngressPacketsRate: 0.05, // 不活跃（低于阈值）
		},
		{
			InterfaceName: "wlan0", // 无活动
		},
	}

	active := FilterActiveInterfaces(stats)

	// 应该只有一个活跃接口
	if len(active) != 1 {
		t.Errorf("FilterActiveInterfaces returned %d interfaces, expected 1", len(active))
	}

	if len(active) > 0 && active[0].InterfaceName != "eth0" {
		t.Errorf("Active interface should be eth0, got %s", active[0].InterfaceName)
	}
}

// abs 返回浮点数的绝对值
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
