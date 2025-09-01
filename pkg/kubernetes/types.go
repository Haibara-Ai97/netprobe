package kubernetes

import (
	"time"
)

// ClusterInfo 集群信息
type ClusterInfo struct {
	NodeCount      int        `json:"node_count"`
	NamespaceCount int        `json:"namespace_count"`
	PodCount       int        `json:"pod_count"`
	ServiceCount   int        `json:"service_count"`
	Nodes          []NodeInfo `json:"nodes"`
	LastUpdated    time.Time  `json:"last_updated"`
}

// NodeInfo 节点信息
type NodeInfo struct {
	Name        string            `json:"name"`
	InternalIP  string            `json:"internal_ip"`
	ExternalIP  string            `json:"external_ip"`
	PodCIDR     string            `json:"pod_cidr"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Ready       bool              `json:"ready"`
}

// PodInfo Pod信息
type PodInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	PodIP       string            `json:"pod_ip"`
	HostIP      string            `json:"host_ip"`
	NodeName    string            `json:"node_name"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Phase       string            `json:"phase"`
	CreatedAt   time.Time         `json:"created_at"`
	Containers  []ContainerInfo   `json:"containers"`
}

// ContainerInfo 容器信息
type ContainerInfo struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Ready bool   `json:"ready"`
}

// ServiceInfo Service信息
type ServiceInfo struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Type        string            `json:"type"`
	ClusterIP   string            `json:"cluster_ip"`
	ExternalIPs []string          `json:"external_ips"`
	Ports       []ServicePort     `json:"ports"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Selector    map[string]string `json:"selector"`
}

// ServicePort 服务端口信息
type ServicePort struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port"`
	NodePort   int32  `json:"node_port,omitempty"`
}

// EndpointInfo Endpoint信息
type EndpointInfo struct {
	ServiceName string           `json:"service_name"`
	Namespace   string           `json:"namespace"`
	Subsets     []EndpointSubset `json:"subsets"`
}

// EndpointSubset Endpoint子集
type EndpointSubset struct {
	Addresses []EndpointAddress `json:"addresses"`
	Ports     []EndpointPort    `json:"ports"`
}

// EndpointAddress Endpoint地址
type EndpointAddress struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	NodeName string `json:"node_name,omitempty"`
	PodName  string `json:"pod_name,omitempty"`
}

// EndpointPort Endpoint端口
type EndpointPort struct {
	Name     string `json:"name"`
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

// NetworkPolicy 网络策略信息
type NetworkPolicy struct {
	Name        string              `json:"name"`
	Namespace   string              `json:"namespace"`
	Labels      map[string]string   `json:"labels"`
	PodSelector map[string]string   `json:"pod_selector"`
	Ingress     []NetworkPolicyRule `json:"ingress"`
	Egress      []NetworkPolicyRule `json:"egress"`
}

// NetworkPolicyRule 网络策略规则
type NetworkPolicyRule struct {
	Ports []NetworkPolicyPort `json:"ports"`
	From  []NetworkPolicyPeer `json:"from"`
	To    []NetworkPolicyPeer `json:"to"`
}

// NetworkPolicyPort 网络策略端口
type NetworkPolicyPort struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
}

// NetworkPolicyPeer 网络策略对等端
type NetworkPolicyPeer struct {
	PodSelector       map[string]string `json:"pod_selector"`
	NamespaceSelector map[string]string `json:"namespace_selector"`
	IPBlock           *IPBlock          `json:"ip_block"`
}

// IPBlock IP块定义
type IPBlock struct {
	CIDR   string   `json:"cidr"`
	Except []string `json:"except"`
}

// FlannelTopology Flannel网络拓扑信息
type FlannelTopology struct {
	Nodes       []FlannelNode   `json:"nodes"`
	Subnets     []FlannelSubnet `json:"subnets"`
	VXLANInfo   VXLANInfo       `json:"vxlan_info"`
	LastUpdated time.Time       `json:"last_updated"`
}

// FlannelNode Flannel节点信息
type FlannelNode struct {
	NodeName    string `json:"node_name"`
	InternalIP  string `json:"internal_ip"`
	PodCIDR     string `json:"pod_cidr"`
	VNI         uint32 `json:"vni"`          // VXLAN Network Identifier
	VTepMAC     string `json:"vtep_mac"`     // VXLAN Tunnel Endpoint MAC
	BackendType string `json:"backend_type"` // vxlan, host-gw, etc.
}

// FlannelSubnet Flannel子网信息
type FlannelSubnet struct {
	Subnet      string                 `json:"subnet"`
	NodeName    string                 `json:"node_name"`
	BackendType string                 `json:"backend_type"`
	BackendData map[string]interface{} `json:"backend_data"`
}

// VXLANInfo VXLAN相关信息
type VXLANInfo struct {
	VNI           uint32            `json:"vni"`
	Port          uint16            `json:"port"`
	GBP           bool              `json:"gbp"`
	DirectRouting bool              `json:"direct_routing"`
	MacPrefix     string            `json:"mac_prefix"`
	Devices       map[string]string `json:"devices"` // node -> device mapping
}

// TrafficFlow 流量流向信息
type TrafficFlow struct {
	SrcPod    *PodInfo     `json:"src_pod,omitempty"`
	DstPod    *PodInfo     `json:"dst_pod,omitempty"`
	SrcNode   *NodeInfo    `json:"src_node,omitempty"`
	DstNode   *NodeInfo    `json:"dst_node,omitempty"`
	Service   *ServiceInfo `json:"service,omitempty"`
	SrcIP     string       `json:"src_ip"`
	DstIP     string       `json:"dst_ip"`
	SrcPort   uint16       `json:"src_port"`
	DstPort   uint16       `json:"dst_port"`
	Protocol  uint8        `json:"protocol"`
	VNI       uint32       `json:"vni,omitempty"` // VXLAN VNI if applicable
	Direction string       `json:"direction"`     // intra-node, inter-node, ingress, egress
	Timestamp time.Time    `json:"timestamp"`
}

// NetworkTopologyMapping 网络拓扑映射
type NetworkTopologyMapping struct {
	IPToPod     map[string]*PodInfo     `json:"ip_to_pod"`
	IPToNode    map[string]*NodeInfo    `json:"ip_to_node"`
	IPToService map[string]*ServiceInfo `json:"ip_to_service"`
	CIDRToNode  map[string]*NodeInfo    `json:"cidr_to_node"`
	VNIToNode   map[uint32]*NodeInfo    `json:"vni_to_node"`
	LastUpdated time.Time               `json:"last_updated"`
}
