package kubernetes

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
)

// K8sNetworkIntegrator Kubernetes网络集成器
type K8sNetworkIntegrator struct {
	client           *Client
	metadataManager  *MetadataManager
	trafficAnalyzer  *TrafficAnalyzer
	vxlanEventChan   chan VXLANEvent
	networkEventChan chan NetworkEvent
	ctx              context.Context
	cancel           context.CancelFunc
	mutex            sync.RWMutex
	started          bool
}

// VXLANEvent VXLAN事件
type VXLANEvent struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  uint8     `json:"protocol"`
	VNI       uint32    `json:"vni"`
	PacketLen uint16    `json:"packet_len"`
	Timestamp time.Time `json:"timestamp"`
}

// NetworkEvent 网络事件
type NetworkEvent struct {
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  uint8     `json:"protocol"`
	PacketLen uint16    `json:"packet_len"`
	Direction string    `json:"direction"`  // ingress, egress
	HookPoint string    `json:"hook_point"` // XDP, TC_INGRESS, TC_EGRESS, etc.
	Timestamp time.Time `json:"timestamp"`
}

// NewK8sNetworkIntegrator 创建Kubernetes网络集成器
func NewK8sNetworkIntegrator(kubeconfig string) (*K8sNetworkIntegrator, error) {
	client, err := NewClient(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	metadataManager := NewMetadataManager(client)
	trafficAnalyzer := NewTrafficAnalyzer(metadataManager)

	ctx, cancel := context.WithCancel(context.Background())

	integrator := &K8sNetworkIntegrator{
		client:           client,
		metadataManager:  metadataManager,
		trafficAnalyzer:  trafficAnalyzer,
		vxlanEventChan:   make(chan VXLANEvent, 1000),
		networkEventChan: make(chan NetworkEvent, 1000),
		ctx:              ctx,
		cancel:           cancel,
	}

	return integrator, nil
}

// Start 启动集成器
func (integrator *K8sNetworkIntegrator) Start() error {
	integrator.mutex.Lock()
	defer integrator.mutex.Unlock()

	if integrator.started {
		return fmt.Errorf("integrator already started")
	}

	// 测试Kubernetes连接
	if err := integrator.client.TestConnection(); err != nil {
		return fmt.Errorf("kubernetes connection test failed: %w", err)
	}

	// 启动元数据管理器
	if err := integrator.metadataManager.Start(); err != nil {
		return fmt.Errorf("failed to start metadata manager: %w", err)
	}

	// 启动事件处理协程
	go integrator.processVXLANEvents()
	go integrator.processNetworkEvents()

	integrator.started = true
	klog.InfoS("Kubernetes network integrator started successfully")
	return nil
}

// Stop 停止集成器
func (integrator *K8sNetworkIntegrator) Stop() {
	integrator.mutex.Lock()
	defer integrator.mutex.Unlock()

	if !integrator.started {
		return
	}

	integrator.cancel()
	integrator.metadataManager.Stop()
	integrator.client.Close()

	close(integrator.vxlanEventChan)
	close(integrator.networkEventChan)

	integrator.started = false
	klog.InfoS("Kubernetes network integrator stopped")
}

// ProcessVXLANEvent 处理VXLAN事件
func (integrator *K8sNetworkIntegrator) ProcessVXLANEvent(srcIP string, dstIP string, srcPort uint16, dstPort uint16, protocol uint8, vni uint32, packetLen uint16) {
	event := VXLANEvent{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		VNI:       vni,
		PacketLen: packetLen,
		Timestamp: time.Now(),
	}

	select {
	case integrator.vxlanEventChan <- event:
	default:
		klog.V(4).InfoS("VXLAN event channel full, dropping event")
	}
}

// ProcessNetworkEvent 处理网络事件
func (integrator *K8sNetworkIntegrator) ProcessNetworkEvent(srcIP string, dstIP string, srcPort uint16, dstPort uint16, protocol uint8, packetLen uint16, direction string, hookPoint string) {
	event := NetworkEvent{
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  protocol,
		PacketLen: packetLen,
		Direction: direction,
		HookPoint: hookPoint,
		Timestamp: time.Now(),
	}

	select {
	case integrator.networkEventChan <- event:
	default:
		klog.V(4).InfoS("Network event channel full, dropping event")
	}
}

// processVXLANEvents 处理VXLAN事件协程
func (integrator *K8sNetworkIntegrator) processVXLANEvents() {
	for {
		select {
		case <-integrator.ctx.Done():
			return
		case event := <-integrator.vxlanEventChan:
			flow := integrator.trafficAnalyzer.AnalyzeVXLANTraffic(
				event.SrcIP, event.DstIP, event.SrcPort, event.DstPort,
				event.Protocol, event.VNI)

			klog.V(3).InfoS("VXLAN traffic analyzed",
				"flow", integrator.trafficAnalyzer.FormatTrafficFlow(flow))
		}
	}
}

// processNetworkEvents 处理网络事件协程
func (integrator *K8sNetworkIntegrator) processNetworkEvents() {
	for {
		select {
		case <-integrator.ctx.Done():
			return
		case event := <-integrator.networkEventChan:
			flow := integrator.trafficAnalyzer.AnalyzeNetworkTraffic(
				event.SrcIP, event.DstIP, event.SrcPort, event.DstPort,
				event.Protocol)

			klog.V(3).InfoS("Network traffic analyzed",
				"flow", integrator.trafficAnalyzer.FormatTrafficFlow(flow),
				"hook_point", event.HookPoint)
		}
	}
}

// GetClusterInfo 获取集群信息
func (integrator *K8sNetworkIntegrator) GetClusterInfo() (*ClusterInfo, error) {
	return integrator.client.GetClusterInfo()
}

// GetTopology 获取网络拓扑
func (integrator *K8sNetworkIntegrator) GetTopology() *NetworkTopologyMapping {
	return integrator.metadataManager.GetTopology()
}

// GetFlannelTopology 获取Flannel拓扑
func (integrator *K8sNetworkIntegrator) GetFlannelTopology() *FlannelTopology {
	return integrator.metadataManager.GetFlannelTopology()
}

// GetTrafficStats 获取流量统计
func (integrator *K8sNetworkIntegrator) GetTrafficStats() *TrafficStats {
	return integrator.trafficAnalyzer.GetStats()
}

// GetFlowsByDirection 根据方向获取流量
func (integrator *K8sNetworkIntegrator) GetFlowsByDirection(direction string) []*TrafficFlow {
	return integrator.trafficAnalyzer.GetFlowsByDirection(direction)
}

// GetFlowsByNamespace 根据命名空间获取流量
func (integrator *K8sNetworkIntegrator) GetFlowsByNamespace(namespace string) []*TrafficFlow {
	return integrator.trafficAnalyzer.GetFlowsByNamespace(namespace)
}

// GetFlowsByNode 根据节点获取流量
func (integrator *K8sNetworkIntegrator) GetFlowsByNode(nodeName string) []*TrafficFlow {
	return integrator.trafficAnalyzer.GetFlowsByNode(nodeName)
}

// GetTopTalkers 获取流量最多的通信对
func (integrator *K8sNetworkIntegrator) GetTopTalkers(limit int) []FlowSummary {
	return integrator.trafficAnalyzer.GetTopTalkers(limit)
}

// QueryPodByIP 根据IP查询Pod信息
func (integrator *K8sNetworkIntegrator) QueryPodByIP(ip string) *PodInfo {
	topology := integrator.metadataManager.GetTopology()
	return topology.IPToPod[ip]
}

// QueryServiceByIP 根据IP查询Service信息
func (integrator *K8sNetworkIntegrator) QueryServiceByIP(ip string) *ServiceInfo {
	topology := integrator.metadataManager.GetTopology()
	return topology.IPToService[ip]
}

// QueryNodeByIP 根据IP查询Node信息
func (integrator *K8sNetworkIntegrator) QueryNodeByIP(ip string) *NodeInfo {
	topology := integrator.metadataManager.GetTopology()
	return topology.IPToNode[ip]
}

// GetNetworkPolicyImpact 获取网络策略影响分析
func (integrator *K8sNetworkIntegrator) GetNetworkPolicyImpact() (*NetworkPolicyImpact, error) {
	// TODO: 实现网络策略影响分析
	return &NetworkPolicyImpact{
		AllowedFlows: 0,
		BlockedFlows: 0,
		Policies:     []string{},
	}, nil
}

// NetworkPolicyImpact 网络策略影响
type NetworkPolicyImpact struct {
	AllowedFlows uint64   `json:"allowed_flows"`
	BlockedFlows uint64   `json:"blocked_flows"`
	Policies     []string `json:"policies"`
}

// GenerateNetworkReport 生成网络报告
func (integrator *K8sNetworkIntegrator) GenerateNetworkReport() *NetworkReport {
	clusterInfo, _ := integrator.GetClusterInfo()
	topology := integrator.GetTopology()
	flannelTopology := integrator.GetFlannelTopology()
	trafficStats := integrator.GetTrafficStats()

	report := &NetworkReport{
		ClusterInfo:     clusterInfo,
		Topology:        topology,
		FlannelTopology: flannelTopology,
		TrafficStats:    trafficStats,
		TopTalkers:      integrator.GetTopTalkers(10),
		GeneratedAt:     time.Now(),
	}

	return report
}

// NetworkReport 网络报告
type NetworkReport struct {
	ClusterInfo     *ClusterInfo            `json:"cluster_info"`
	Topology        *NetworkTopologyMapping `json:"topology"`
	FlannelTopology *FlannelTopology        `json:"flannel_topology"`
	TrafficStats    *TrafficStats           `json:"traffic_stats"`
	TopTalkers      []FlowSummary           `json:"top_talkers"`
	GeneratedAt     time.Time               `json:"generated_at"`
}

// IsVXLANTraffic 检查是否为VXLAN流量
func IsVXLANTraffic(port uint16) bool {
	// 常见的VXLAN端口
	return port == 4789 || port == 8472
}

// ExtractVNIFromPacket 从数据包中提取VNI (简化版本)
func ExtractVNIFromPacket(data []byte) uint32 {
	// VXLAN头部格式简化解析
	if len(data) < 8 {
		return 0
	}

	// VXLAN头部中VNI字段位于字节4-6
	if len(data) >= 8 {
		vni := uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6])
		return vni >> 8 // VNI是24位
	}

	return 0
}
