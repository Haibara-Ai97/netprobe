package collector

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatBytes 格式化字节数为人类可读的格式
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/TB)
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// FormatRate 格式化速率
func FormatRate(rate float64, unit string) string {
	const (
		K = 1000
		M = K * 1000
		G = M * 1000
	)

	switch {
	case rate >= G:
		return fmt.Sprintf("%.2f G%s/s", rate/G, unit)
	case rate >= M:
		return fmt.Sprintf("%.2f M%s/s", rate/M, unit)
	case rate >= K:
		return fmt.Sprintf("%.2f K%s/s", rate/K, unit)
	default:
		return fmt.Sprintf("%.2f %s/s", rate, unit)
	}
}

// FormatPacketRate 格式化包速率
func FormatPacketRate(packetsPerSec float64) string {
	return FormatRate(packetsPerSec, "pkt")
}

// FormatBytesRate 格式化字节速率
func FormatBytesRate(bytesPerSec float64) string {
	return FormatRate(bytesPerSec, "B")
}

// String 格式化显示接口统计信息
func (is *InterfaceStats) String() string {
	return fmt.Sprintf(
		"Interface: %s (idx:%d)\n"+
			"  Ingress: %d pkts (%s) | Rate: %s, %s\n"+
			"  Egress:  %d pkts (%s) | Rate: %s, %s\n"+
			"  Updated: %s",
		is.InterfaceName, is.InterfaceIndex,
		is.IngressPackets, FormatBytes(is.IngressBytes),
		FormatPacketRate(is.IngressPacketsRate), FormatBytesRate(is.IngressBytesRate),
		is.EgressPackets, FormatBytes(is.EgressBytes),
		FormatPacketRate(is.EgressPacketsRate), FormatBytesRate(is.EgressBytesRate),
		is.LastUpdated.Format("15:04:05"))
}

// Summary 返回接口统计的简要信息
func (is *InterfaceStats) Summary() string {
	return fmt.Sprintf("%s: IN=%s OUT=%s",
		is.InterfaceName,
		FormatBytesRate(is.IngressBytesRate),
		FormatBytesRate(is.EgressBytesRate))
}

// HasTraffic 检查接口是否有流量
func (is *InterfaceStats) HasTraffic() bool {
	return is.IngressPackets > 0 || is.EgressPackets > 0
}

// HasActivity 检查接口是否有活跃流量（基于速率）
func (is *InterfaceStats) HasActivity() bool {
	threshold := 0.1 // 每秒 0.1 包的阈值
	return is.IngressPacketsRate > threshold || is.EgressPacketsRate > threshold
}

// TotalPackets 返回总包数
func (is *InterfaceStats) TotalPackets() uint64 {
	return is.IngressPackets + is.EgressPackets
}

// TotalBytes 返回总字节数
func (is *InterfaceStats) TotalBytes() uint64 {
	return is.IngressBytes + is.EgressBytes
}

// TotalPacketsRate 返回总包速率
func (is *InterfaceStats) TotalPacketsRate() float64 {
	return is.IngressPacketsRate + is.EgressPacketsRate
}

// TotalBytesRate 返回总字节速率
func (is *InterfaceStats) TotalBytesRate() float64 {
	return is.IngressBytesRate + is.EgressBytesRate
}

// CollectionSummary 收集结果摘要
type CollectionSummary struct {
	TotalInterfaces   int
	ActiveInterfaces  int
	TotalPackets      uint64
	TotalBytes        uint64
	TotalPacketsRate  float64
	TotalBytesRate    float64
	TopInterfaces     []InterfaceStats
	CollectionTime    time.Time
}

// SummarizeCollection 创建收集结果摘要
func SummarizeCollection(stats []InterfaceStats, topN int) *CollectionSummary {
	summary := &CollectionSummary{
		TotalInterfaces: len(stats),
		CollectionTime:  time.Now(),
	}

	// 计算总计和活跃接口
	for _, stat := range stats {
		summary.TotalPackets += stat.TotalPackets()
		summary.TotalBytes += stat.TotalBytes()
		summary.TotalPacketsRate += stat.TotalPacketsRate()
		summary.TotalBytesRate += stat.TotalBytesRate()

		if stat.HasActivity() {
			summary.ActiveInterfaces++
		}
	}

	// 按总字节速率排序，获取 Top N
	sortedStats := make([]InterfaceStats, len(stats))
	copy(sortedStats, stats)

	sort.Slice(sortedStats, func(i, j int) bool {
		return sortedStats[i].TotalBytesRate() > sortedStats[j].TotalBytesRate()
	})

	if topN > len(sortedStats) {
		topN = len(sortedStats)
	}
	summary.TopInterfaces = sortedStats[:topN]

	return summary
}

// String 格式化显示摘要
func (cs *CollectionSummary) String() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Collection Summary (%s):\n",
		cs.CollectionTime.Format("15:04:05")))
	sb.WriteString(fmt.Sprintf("  Total Interfaces: %d (Active: %d)\n",
		cs.TotalInterfaces, cs.ActiveInterfaces))
	sb.WriteString(fmt.Sprintf("  Total Traffic: %s (%s)\n",
		FormatBytes(cs.TotalBytes), FormatBytesRate(cs.TotalBytesRate)))
	sb.WriteString(fmt.Sprintf("  Total Packets: %d (%s)\n",
		cs.TotalPackets, FormatPacketRate(cs.TotalPacketsRate)))

	if len(cs.TopInterfaces) > 0 {
		sb.WriteString("  Top Interfaces by Traffic:\n")
		for i, iface := range cs.TopInterfaces {
			if iface.HasActivity() {
				sb.WriteString(fmt.Sprintf("    %d. %s\n", i+1, iface.Summary()))
			}
		}
	}

	return sb.String()
}

// DetailedString 返回详细的摘要信息
func (cs *CollectionSummary) DetailedString() string {
	var sb strings.Builder

	sb.WriteString(cs.String())
	sb.WriteString("\nDetailed Interface Stats:\n")

	for _, iface := range cs.TopInterfaces {
		if iface.HasTraffic() {
			sb.WriteString(fmt.Sprintf("  %s\n", iface.String()))
		}
	}

	return sb.String()
}

// FilterActiveInterfaces 过滤出有活跃流量的接口
func FilterActiveInterfaces(stats []InterfaceStats) []InterfaceStats {
	var active []InterfaceStats
	for _, stat := range stats {
		if stat.HasActivity() {
			active = append(active, stat)
		}
	}
	return active
}

// FilterInterfacesByName 按接口名过滤
func FilterInterfacesByName(stats []InterfaceStats, names []string) []InterfaceStats {
	nameSet := make(map[string]bool)
	for _, name := range names {
		nameSet[name] = true
	}

	var filtered []InterfaceStats
	for _, stat := range stats {
		if nameSet[stat.InterfaceName] {
			filtered = append(filtered, stat)
		}
	}
	return filtered
}

// SortInterfacesByBytesRate 按字节速率排序接口
func SortInterfacesByBytesRate(stats []InterfaceStats, descending bool) {
	sort.Slice(stats, func(i, j int) bool {
		if descending {
			return stats[i].TotalBytesRate() > stats[j].TotalBytesRate()
		}
		return stats[i].TotalBytesRate() < stats[j].TotalBytesRate()
	})
}

// SortInterfacesByPacketsRate 按包速率排序接口
func SortInterfacesByPacketsRate(stats []InterfaceStats, descending bool) {
	sort.Slice(stats, func(i, j int) bool {
		if descending {
			return stats[i].TotalPacketsRate() > stats[j].TotalPacketsRate()
		}
		return stats[i].TotalPacketsRate() < stats[j].TotalPacketsRate()
	})
}
