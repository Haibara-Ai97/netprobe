package kubernetes

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// TrafficAnalyzer 流量分析器
type TrafficAnalyzer struct {
	metadataManager *MetadataManager
	mutex           sync.RWMutex
	flowCache       map[string]*TrafficFlow
	stats           *TrafficStats
}

// TrafficStats 流量统计
type TrafficStats struct {
	TotalFlows        uint64                       `json:"total_flows"`
	IntraNodeFlows    uint64                       `json:"intra_node_flows"`
	InterNodeFlows    uint64                       `json:"inter_node_flows"`
	PodToPodFlows     uint64                       `json:"pod_to_pod_flows"`
	ServiceFlows      uint64                       `json:"service_flows"`
	ExternalFlows     uint64                       `json:"external_flows"`
	VXLANFlows        uint64                       `json:"vxlan_flows"`
	ProtocolDistrib   map[uint8]uint64             `json:"protocol_distribution"`
	PortDistrib       map[uint16]uint64            `json:"port_distribution"`
	NodeTrafficMatrix map[string]map[string]uint64 `json:"node_traffic_matrix"`
	LastUpdated       time.Time                    `json:"last_updated"`
}

// NewTrafficAnalyzer 创建流量分析器
func NewTrafficAnalyzer(metadataManager *MetadataManager) *TrafficAnalyzer {
	return &TrafficAnalyzer{
		metadataManager: metadataManager,
		flowCache:       make(map[string]*TrafficFlow),
		stats: &TrafficStats{
			ProtocolDistrib:   make(map[uint8]uint64),
			PortDistrib:       make(map[uint16]uint64),
			NodeTrafficMatrix: make(map[string]map[string]uint64),
		},
	}
}

// AnalyzeVXLANTraffic 分析VXLAN流量
func (ta *TrafficAnalyzer) AnalyzeVXLANTraffic(srcIP string, dstIP string, srcPort uint16, dstPort uint16, protocol uint8, vni uint32) *TrafficFlow {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	// 创建流量流向对象
	flow := &TrafficFlow{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		VNI:       vni,
		Timestamp: time.Now(),
	}

	// 获取网络拓扑映射
	topology := ta.metadataManager.GetTopology()

	// 查找源和目标信息
	flow.SrcPod = topology.IPToPod[srcIP]
	flow.DstPod = topology.IPToPod[dstIP]
	flow.Service = topology.IPToService[dstIP]

	// 查找节点信息
	flow.SrcNode = ta.findNodeForIP(srcIP, topology)
	flow.DstNode = ta.findNodeForIP(dstIP, topology)

	// 确定流量方向
	flow.Direction = ta.determineDirection(flow)

	// 更新统计信息
	ta.updateStats(flow)

	// 缓存流量信息
	flowKey := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	ta.flowCache[flowKey] = flow

	return flow
}

// AnalyzeNetworkTraffic 分析一般网络流量
func (ta *TrafficAnalyzer) AnalyzeNetworkTraffic(srcIP string, dstIP string, srcPort uint16, dstPort uint16, protocol uint8) *TrafficFlow {
	return ta.AnalyzeVXLANTraffic(srcIP, dstIP, srcPort, dstPort, protocol, 0)
}

// findNodeForIP 根据IP查找节点
func (ta *TrafficAnalyzer) findNodeForIP(ip string, topology *NetworkTopologyMapping) *NodeInfo {
	// 直接IP匹配
	if node := topology.IPToNode[ip]; node != nil {
		return node
	}

	// 通过Pod查找节点
	if pod := topology.IPToPod[ip]; pod != nil {
		if node := topology.IPToNode[pod.HostIP]; node != nil {
			return node
		}
		// 通过节点名查找
		for _, node := range topology.IPToNode {
			if node.Name == pod.NodeName {
				return node
			}
		}
	}

	// 通过CIDR匹配
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		for cidr, node := range topology.CIDRToNode {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err == nil && ipNet.Contains(parsedIP) {
				return node
			}
		}
	}

	return nil
}

// determineDirection 确定流量方向
func (ta *TrafficAnalyzer) determineDirection(flow *TrafficFlow) string {
	// 如果有Service信息，可能是服务流量
	if flow.Service != nil {
		return "service"
	}

	// Pod到Pod流量
	if flow.SrcPod != nil && flow.DstPod != nil {
		if flow.SrcNode != nil && flow.DstNode != nil {
			if flow.SrcNode.Name == flow.DstNode.Name {
				return "intra-node"
			} else {
				return "inter-node"
			}
		}
		return "pod-to-pod"
	}

	// 入站流量
	if flow.SrcPod == nil && flow.DstPod != nil {
		return "ingress"
	}

	// 出站流量
	if flow.SrcPod != nil && flow.DstPod == nil {
		return "egress"
	}

	// 外部流量
	return "external"
}

// updateStats 更新统计信息
func (ta *TrafficAnalyzer) updateStats(flow *TrafficFlow) {
	ta.stats.TotalFlows++

	switch flow.Direction {
	case "intra-node":
		ta.stats.IntraNodeFlows++
	case "inter-node":
		ta.stats.InterNodeFlows++
	case "pod-to-pod":
		ta.stats.PodToPodFlows++
	case "service":
		ta.stats.ServiceFlows++
	case "external", "ingress", "egress":
		ta.stats.ExternalFlows++
	}

	if flow.VNI > 0 {
		ta.stats.VXLANFlows++
	}

	// 协议分布
	ta.stats.ProtocolDistrib[flow.Protocol]++

	// 端口分布
	ta.stats.PortDistrib[flow.DstPort]++

	// 节点流量矩阵
	if flow.SrcNode != nil && flow.DstNode != nil {
		srcNode := flow.SrcNode.Name
		dstNode := flow.DstNode.Name

		if ta.stats.NodeTrafficMatrix[srcNode] == nil {
			ta.stats.NodeTrafficMatrix[srcNode] = make(map[string]uint64)
		}
		ta.stats.NodeTrafficMatrix[srcNode][dstNode]++
	}

	ta.stats.LastUpdated = time.Now()
}

// GetStats 获取流量统计信息
func (ta *TrafficAnalyzer) GetStats() *TrafficStats {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	// 创建深拷贝
	stats := &TrafficStats{
		TotalFlows:        ta.stats.TotalFlows,
		IntraNodeFlows:    ta.stats.IntraNodeFlows,
		InterNodeFlows:    ta.stats.InterNodeFlows,
		PodToPodFlows:     ta.stats.PodToPodFlows,
		ServiceFlows:      ta.stats.ServiceFlows,
		ExternalFlows:     ta.stats.ExternalFlows,
		VXLANFlows:        ta.stats.VXLANFlows,
		ProtocolDistrib:   make(map[uint8]uint64),
		PortDistrib:       make(map[uint16]uint64),
		NodeTrafficMatrix: make(map[string]map[string]uint64),
		LastUpdated:       ta.stats.LastUpdated,
	}

	for k, v := range ta.stats.ProtocolDistrib {
		stats.ProtocolDistrib[k] = v
	}
	for k, v := range ta.stats.PortDistrib {
		stats.PortDistrib[k] = v
	}
	for srcNode, dstMap := range ta.stats.NodeTrafficMatrix {
		stats.NodeTrafficMatrix[srcNode] = make(map[string]uint64)
		for dstNode, count := range dstMap {
			stats.NodeTrafficMatrix[srcNode][dstNode] = count
		}
	}

	return stats
}

// GetFlowsByDirection 根据方向获取流量
func (ta *TrafficAnalyzer) GetFlowsByDirection(direction string) []*TrafficFlow {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	var flows []*TrafficFlow
	for _, flow := range ta.flowCache {
		if flow.Direction == direction {
			flows = append(flows, flow)
		}
	}

	return flows
}

// GetFlowsByNamespace 根据命名空间获取流量
func (ta *TrafficAnalyzer) GetFlowsByNamespace(namespace string) []*TrafficFlow {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	var flows []*TrafficFlow
	for _, flow := range ta.flowCache {
		if (flow.SrcPod != nil && flow.SrcPod.Namespace == namespace) ||
			(flow.DstPod != nil && flow.DstPod.Namespace == namespace) ||
			(flow.Service != nil && flow.Service.Namespace == namespace) {
			flows = append(flows, flow)
		}
	}

	return flows
}

// GetFlowsByNode 根据节点获取流量
func (ta *TrafficAnalyzer) GetFlowsByNode(nodeName string) []*TrafficFlow {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	var flows []*TrafficFlow
	for _, flow := range ta.flowCache {
		if (flow.SrcNode != nil && flow.SrcNode.Name == nodeName) ||
			(flow.DstNode != nil && flow.DstNode.Name == nodeName) {
			flows = append(flows, flow)
		}
	}

	return flows
}

// GetTopTalkers 获取流量最多的通信对
func (ta *TrafficAnalyzer) GetTopTalkers(limit int) []FlowSummary {
	ta.mutex.RLock()
	defer ta.mutex.RUnlock()

	flowCounts := make(map[string]uint64)
	flowInfo := make(map[string]*TrafficFlow)

	for _, flow := range ta.flowCache {
		key := fmt.Sprintf("%s->%s", flow.SrcIP, flow.DstIP)
		flowCounts[key]++
		if flowInfo[key] == nil {
			flowInfo[key] = flow
		}
	}

	// 排序并返回前N个
	var summaries []FlowSummary
	for key, count := range flowCounts {
		if len(summaries) >= limit {
			break
		}

		flow := flowInfo[key]
		summary := FlowSummary{
			SrcIP:     flow.SrcIP,
			DstIP:     flow.DstIP,
			FlowCount: count,
			Direction: flow.Direction,
		}

		if flow.SrcPod != nil {
			summary.SrcInfo = fmt.Sprintf("%s/%s", flow.SrcPod.Namespace, flow.SrcPod.Name)
		}
		if flow.DstPod != nil {
			summary.DstInfo = fmt.Sprintf("%s/%s", flow.DstPod.Namespace, flow.DstPod.Name)
		}
		if flow.Service != nil {
			summary.DstInfo = fmt.Sprintf("svc/%s/%s", flow.Service.Namespace, flow.Service.Name)
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// FlowSummary 流量摘要
type FlowSummary struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcInfo   string `json:"src_info"`
	DstInfo   string `json:"dst_info"`
	FlowCount uint64 `json:"flow_count"`
	Direction string `json:"direction"`
}

// ClearCache 清空流量缓存
func (ta *TrafficAnalyzer) ClearCache() {
	ta.mutex.Lock()
	defer ta.mutex.Unlock()

	ta.flowCache = make(map[string]*TrafficFlow)
	klog.InfoS("Traffic flow cache cleared")
}

// GetProtocolName 获取协议名称
func GetProtocolName(protocol uint8) string {
	switch protocol {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("Proto-%d", protocol)
	}
}

// FormatTrafficFlow 格式化流量信息
func (ta *TrafficAnalyzer) FormatTrafficFlow(flow *TrafficFlow) string {
	var srcDesc, dstDesc string

	// 格式化源信息
	if flow.SrcPod != nil {
		srcDesc = fmt.Sprintf("%s/%s(%s)", flow.SrcPod.Namespace, flow.SrcPod.Name, flow.SrcIP)
	} else if flow.SrcNode != nil {
		srcDesc = fmt.Sprintf("node/%s(%s)", flow.SrcNode.Name, flow.SrcIP)
	} else {
		srcDesc = flow.SrcIP
	}

	// 格式化目标信息
	if flow.Service != nil {
		dstDesc = fmt.Sprintf("svc/%s/%s(%s)", flow.Service.Namespace, flow.Service.Name, flow.DstIP)
	} else if flow.DstPod != nil {
		dstDesc = fmt.Sprintf("%s/%s(%s)", flow.DstPod.Namespace, flow.DstPod.Name, flow.DstIP)
	} else if flow.DstNode != nil {
		dstDesc = fmt.Sprintf("node/%s(%s)", flow.DstNode.Name, flow.DstIP)
	} else {
		dstDesc = flow.DstIP
	}

	protocol := GetProtocolName(flow.Protocol)
	vniInfo := ""
	if flow.VNI > 0 {
		vniInfo = fmt.Sprintf(" VNI:%d", flow.VNI)
	}

	return fmt.Sprintf("[%s] %s %s:%d -> %s:%d (%s)%s",
		strings.ToUpper(flow.Direction), protocol, srcDesc, flow.SrcPort, dstDesc, flow.DstPort,
		flow.Timestamp.Format("15:04:05"), vniInfo)
}
