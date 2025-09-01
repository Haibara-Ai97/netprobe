package kubernetes

import (
	"context"
	"fmt"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// MetadataManager Kubernetes元数据管理器
type MetadataManager struct {
	client          *Client
	topology        *NetworkTopologyMapping
	flannelTopology *FlannelTopology
	mutex           sync.RWMutex
	informers       map[string]cache.SharedInformer
	stopCh          chan struct{}
	updateCh        chan struct{}
}

// NewMetadataManager 创建元数据管理器
func NewMetadataManager(client *Client) *MetadataManager {
	return &MetadataManager{
		client: client,
		topology: &NetworkTopologyMapping{
			IPToPod:     make(map[string]*PodInfo),
			IPToNode:    make(map[string]*NodeInfo),
			IPToService: make(map[string]*ServiceInfo),
			CIDRToNode:  make(map[string]*NodeInfo),
			VNIToNode:   make(map[uint32]*NodeInfo),
		},
		flannelTopology: &FlannelTopology{
			Nodes:   []FlannelNode{},
			Subnets: []FlannelSubnet{},
		},
		informers: make(map[string]cache.SharedInformer),
		stopCh:    make(chan struct{}),
		updateCh:  make(chan struct{}, 100),
	}
}

// Start 启动元数据管理器
func (mm *MetadataManager) Start() error {
	// 初始化数据
	if err := mm.initialSync(); err != nil {
		return fmt.Errorf("initial sync failed: %w", err)
	}

	// 启动Informers
	mm.startInformers()

	// 启动更新协程
	go mm.updateLoop()

	klog.InfoS("Metadata manager started successfully")
	return nil
}

// Stop 停止元数据管理器
func (mm *MetadataManager) Stop() {
	close(mm.stopCh)
	klog.InfoS("Metadata manager stopped")
}

// initialSync 初始同步
func (mm *MetadataManager) initialSync() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 同步Nodes
	if err := mm.syncNodes(ctx); err != nil {
		return fmt.Errorf("sync nodes failed: %w", err)
	}

	// 同步Pods
	if err := mm.syncPods(ctx); err != nil {
		return fmt.Errorf("sync pods failed: %w", err)
	}

	// 同步Services
	if err := mm.syncServices(ctx); err != nil {
		return fmt.Errorf("sync services failed: %w", err)
	}

	// 构建Flannel拓扑
	if err := mm.buildFlannelTopology(ctx); err != nil {
		klog.ErrorS(err, "Failed to build flannel topology")
		// 非致命错误，继续执行
	}

	mm.topology.LastUpdated = time.Now()
	klog.InfoS("Initial sync completed", "pods", len(mm.topology.IPToPod),
		"nodes", len(mm.topology.IPToNode), "services", len(mm.topology.IPToService))

	return nil
}

// syncNodes 同步节点信息
func (mm *MetadataManager) syncNodes(ctx context.Context) error {
	nodes, err := mm.client.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	// 清空现有映射
	mm.topology.IPToNode = make(map[string]*NodeInfo)
	mm.topology.CIDRToNode = make(map[string]*NodeInfo)

	for _, node := range nodes.Items {
		nodeInfo := mm.convertNodeInfo(&node)

		// IP映射
		if nodeInfo.InternalIP != "" {
			mm.topology.IPToNode[nodeInfo.InternalIP] = nodeInfo
		}
		if nodeInfo.ExternalIP != "" {
			mm.topology.IPToNode[nodeInfo.ExternalIP] = nodeInfo
		}

		// CIDR映射
		if nodeInfo.PodCIDR != "" {
			mm.topology.CIDRToNode[nodeInfo.PodCIDR] = nodeInfo
		}
	}

	return nil
}

// syncPods 同步Pod信息
func (mm *MetadataManager) syncPods(ctx context.Context) error {
	pods, err := mm.client.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	// 清空现有映射
	mm.topology.IPToPod = make(map[string]*PodInfo)

	for _, pod := range pods.Items {
		if pod.Status.PodIP != "" && pod.Status.Phase == corev1.PodRunning {
			podInfo := mm.convertPodInfo(&pod)
			mm.topology.IPToPod[pod.Status.PodIP] = podInfo
		}
	}

	return nil
}

// syncServices 同步Service信息
func (mm *MetadataManager) syncServices(ctx context.Context) error {
	services, err := mm.client.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	// 清空现有映射
	mm.topology.IPToService = make(map[string]*ServiceInfo)

	for _, service := range services.Items {
		if service.Spec.ClusterIP != "" && service.Spec.ClusterIP != "None" {
			serviceInfo := mm.convertServiceInfo(&service)
			mm.topology.IPToService[service.Spec.ClusterIP] = serviceInfo

			// 处理ExternalIPs
			for _, externalIP := range service.Spec.ExternalIPs {
				mm.topology.IPToService[externalIP] = serviceInfo
			}
		}
	}

	return nil
}

// convertNodeInfo 转换Node信息
func (mm *MetadataManager) convertNodeInfo(node *corev1.Node) *NodeInfo {
	nodeInfo := &NodeInfo{
		Name:        node.Name,
		PodCIDR:     node.Spec.PodCIDR,
		Labels:      node.Labels,
		Annotations: node.Annotations,
		Ready:       false,
	}

	// 获取节点IP
	for _, addr := range node.Status.Addresses {
		switch addr.Type {
		case corev1.NodeInternalIP:
			nodeInfo.InternalIP = addr.Address
		case corev1.NodeExternalIP:
			nodeInfo.ExternalIP = addr.Address
		}
	}

	// 检查节点状态
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			nodeInfo.Ready = true
			break
		}
	}

	return nodeInfo
}

// convertPodInfo 转换Pod信息
func (mm *MetadataManager) convertPodInfo(pod *corev1.Pod) *PodInfo {
	podInfo := &PodInfo{
		Name:        pod.Name,
		Namespace:   pod.Namespace,
		PodIP:       pod.Status.PodIP,
		HostIP:      pod.Status.HostIP,
		NodeName:    pod.Spec.NodeName,
		Labels:      pod.Labels,
		Annotations: pod.Annotations,
		Phase:       string(pod.Status.Phase),
		CreatedAt:   pod.CreationTimestamp.Time,
		Containers:  make([]ContainerInfo, len(pod.Spec.Containers)),
	}

	// 转换容器信息
	for i, container := range pod.Spec.Containers {
		containerInfo := ContainerInfo{
			Name:  container.Name,
			Image: container.Image,
			Ready: false,
		}

		// 检查容器状态
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == container.Name {
				containerInfo.Ready = status.Ready
				break
			}
		}

		podInfo.Containers[i] = containerInfo
	}

	return podInfo
}

// convertServiceInfo 转换Service信息
func (mm *MetadataManager) convertServiceInfo(service *corev1.Service) *ServiceInfo {
	serviceInfo := &ServiceInfo{
		Name:        service.Name,
		Namespace:   service.Namespace,
		Type:        string(service.Spec.Type),
		ClusterIP:   service.Spec.ClusterIP,
		ExternalIPs: service.Spec.ExternalIPs,
		Labels:      service.Labels,
		Annotations: service.Annotations,
		Selector:    service.Spec.Selector,
		Ports:       make([]ServicePort, len(service.Spec.Ports)),
	}

	// 转换端口信息
	for i, port := range service.Spec.Ports {
		serviceInfo.Ports[i] = ServicePort{
			Name:       port.Name,
			Protocol:   string(port.Protocol),
			Port:       port.Port,
			TargetPort: port.TargetPort.String(),
			NodePort:   port.NodePort,
		}
	}

	return serviceInfo
}

// GetTopology 获取网络拓扑映射
func (mm *MetadataManager) GetTopology() *NetworkTopologyMapping {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	// 创建深拷贝
	topology := &NetworkTopologyMapping{
		IPToPod:     make(map[string]*PodInfo),
		IPToNode:    make(map[string]*NodeInfo),
		IPToService: make(map[string]*ServiceInfo),
		CIDRToNode:  make(map[string]*NodeInfo),
		VNIToNode:   make(map[uint32]*NodeInfo),
		LastUpdated: mm.topology.LastUpdated,
	}

	for k, v := range mm.topology.IPToPod {
		topology.IPToPod[k] = v
	}
	for k, v := range mm.topology.IPToNode {
		topology.IPToNode[k] = v
	}
	for k, v := range mm.topology.IPToService {
		topology.IPToService[k] = v
	}
	for k, v := range mm.topology.CIDRToNode {
		topology.CIDRToNode[k] = v
	}
	for k, v := range mm.topology.VNIToNode {
		topology.VNIToNode[k] = v
	}

	return topology
}

// GetFlannelTopology 获取Flannel拓扑信息
func (mm *MetadataManager) GetFlannelTopology() *FlannelTopology {
	mm.mutex.RLock()
	defer mm.mutex.RUnlock()

	// 创建深拷贝
	topology := &FlannelTopology{
		Nodes:       make([]FlannelNode, len(mm.flannelTopology.Nodes)),
		Subnets:     make([]FlannelSubnet, len(mm.flannelTopology.Subnets)),
		VXLANInfo:   mm.flannelTopology.VXLANInfo,
		LastUpdated: mm.flannelTopology.LastUpdated,
	}

	copy(topology.Nodes, mm.flannelTopology.Nodes)
	copy(topology.Subnets, mm.flannelTopology.Subnets)

	return topology
}

// updateLoop 更新循环
func (mm *MetadataManager) updateLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mm.stopCh:
			return
		case <-ticker.C:
			// 定期全量同步
			if err := mm.initialSync(); err != nil {
				klog.ErrorS(err, "Periodic sync failed")
			}
		case <-mm.updateCh:
			// 增量更新
			mm.topology.LastUpdated = time.Now()
		}
	}
}

// startInformers 启动informers (简化版本，暂时不实现)
func (mm *MetadataManager) startInformers() {
	// TODO: 实现informers监听资源变化
	klog.InfoS("Informers started (simplified mode)")
}

// buildFlannelTopology 构建Flannel拓扑
func (mm *MetadataManager) buildFlannelTopology(ctx context.Context) error {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	// 清空现有数据
	mm.flannelTopology.Nodes = []FlannelNode{}
	mm.flannelTopology.Subnets = []FlannelSubnet{}
	mm.flannelTopology.VXLANInfo = VXLANInfo{
		VNI:           1,    // 默认VNI
		Port:          8472, // 默认VXLAN端口
		GBP:           false,
		DirectRouting: false,
		MacPrefix:     "0e:2a",
		Devices:       make(map[string]string),
	}

	// 获取所有节点
	nodes, err := mm.client.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	// 查找Flannel相关的ConfigMap或DaemonSet配置
	configMaps, err := mm.client.clientset.CoreV1().ConfigMaps("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.V(2).InfoS("Failed to list configmaps in kube-system", "error", err)
	}

	// 解析Flannel配置
	flannelConfig := mm.parseFlannelConfig(configMaps.Items)

	// 构建节点拓扑
	for _, node := range nodes.Items {
		if node.Spec.PodCIDR == "" {
			continue
		}

		flannelNode := FlannelNode{
			NodeName:    node.Name,
			PodCIDR:     node.Spec.PodCIDR,
			VNI:         flannelConfig.VNI,
			BackendType: flannelConfig.BackendType,
		}

		// 获取节点内网IP
		for _, addr := range node.Status.Addresses {
			if addr.Type == corev1.NodeInternalIP {
				flannelNode.InternalIP = addr.Address
				break
			}
		}

		// 生成VTEP MAC (简化版本)
		if flannelNode.InternalIP != "" {
			flannelNode.VTepMAC = fmt.Sprintf("%s:%02x:%02x",
				flannelConfig.MacPrefix,
				ipToUint32(flannelNode.InternalIP)>>8&0xFF,
				ipToUint32(flannelNode.InternalIP)&0xFF)
		}

		mm.flannelTopology.Nodes = append(mm.flannelTopology.Nodes, flannelNode)

		// 构建子网信息
		subnet := FlannelSubnet{
			Subnet:      node.Spec.PodCIDR,
			NodeName:    node.Name,
			BackendType: flannelConfig.BackendType,
			BackendData: map[string]interface{}{
				"VtepMAC":  flannelNode.VTepMAC,
				"PublicIP": flannelNode.InternalIP,
			},
		}
		mm.flannelTopology.Subnets = append(mm.flannelTopology.Subnets, subnet)

		// 更新VNI到节点的映射
		if nodeInfo, exists := mm.topology.IPToNode[flannelNode.InternalIP]; exists {
			mm.topology.VNIToNode[flannelConfig.VNI] = nodeInfo
		}
	}

	mm.flannelTopology.LastUpdated = time.Now()
	klog.InfoS("Flannel topology built", "nodes", len(mm.flannelTopology.Nodes),
		"subnets", len(mm.flannelTopology.Subnets))

	return nil
}

// FlannelConfig Flannel配置
type FlannelConfig struct {
	VNI         uint32
	BackendType string
	MacPrefix   string
}

// parseFlannelConfig 解析Flannel配置
func (mm *MetadataManager) parseFlannelConfig(configMaps []corev1.ConfigMap) FlannelConfig {
	config := FlannelConfig{
		VNI:         1,       // 默认值
		BackendType: "vxlan", // 默认后端
		MacPrefix:   "0e:2a", // 默认MAC前缀
	}

	// 查找flannel配置
	for _, cm := range configMaps {
		if cm.Name == "kube-flannel-cfg" || cm.Name == "flannel-cfg" {
			if netConf, exists := cm.Data["net-conf.json"]; exists {
				klog.V(2).InfoS("Found flannel config", "config", netConf)
				// TODO: 解析JSON配置，提取VNI、Backend等信息
				// 这里使用简化版本
			}
		}
	}

	return config
}
