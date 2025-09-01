package kubernetes

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
)

// Client Kubernetes客户端封装
type Client struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewClient 创建新的Kubernetes客户端
func NewClient(kubeconfig string) (*Client, error) {
	var config *rest.Config
	var err error

	if kubeconfig == "" {
		// 尝试使用集群内配置
		config, err = rest.InClusterConfig()
		if err != nil {
			klog.V(2).Infof("Failed to use in-cluster config: %v", err)
			// 使用默认kubeconfig路径
			config, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
			if err != nil {
				return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
			}
		}
	} else {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubeconfig from %s: %w", kubeconfig, err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		clientset: clientset,
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
	}

	klog.InfoS("Kubernetes client initialized successfully")
	return client, nil
}

// Close 关闭客户端
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
}

// GetClientset 获取kubernetes客户端集
func (c *Client) GetClientset() *kubernetes.Clientset {
	return c.clientset
}

// TestConnection 测试与API Server的连接
func (c *Client) TestConnection() error {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()

	_, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		return fmt.Errorf("failed to connect to kubernetes API server: %w", err)
	}

	klog.InfoS("Successfully connected to Kubernetes API server")
	return nil
}

// GetClusterInfo 获取集群基本信息
func (c *Client) GetClusterInfo() (*ClusterInfo, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	// 获取节点信息
	nodes, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// 获取命名空间信息
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// 获取Pod统计信息
	pods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// 获取Service统计信息
	services, err := c.clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	clusterInfo := &ClusterInfo{
		NodeCount:      len(nodes.Items),
		NamespaceCount: len(namespaces.Items),
		PodCount:       len(pods.Items),
		ServiceCount:   len(services.Items),
		Nodes:          make([]NodeInfo, len(nodes.Items)),
		LastUpdated:    time.Now(),
	}

	// 构建节点信息
	for i, node := range nodes.Items {
		nodeInfo := NodeInfo{
			Name:        node.Name,
			InternalIP:  "",
			ExternalIP:  "",
			PodCIDR:     node.Spec.PodCIDR,
			Labels:      node.Labels,
			Annotations: node.Annotations,
			Ready:       false,
		}

		// 获取节点IP
		for _, addr := range node.Status.Addresses {
			switch addr.Type {
			case "InternalIP":
				nodeInfo.InternalIP = addr.Address
			case "ExternalIP":
				nodeInfo.ExternalIP = addr.Address
			}
		}

		// 检查节点状态
		for _, condition := range node.Status.Conditions {
			if condition.Type == "Ready" && condition.Status == "True" {
				nodeInfo.Ready = true
				break
			}
		}

		clusterInfo.Nodes[i] = nodeInfo
	}

	return clusterInfo, nil
}

// ipToUint32 将IP地址转换为uint32
func ipToUint32(ip string) uint32 {
	ipNet := net.ParseIP(ip)
	if ipNet == nil {
		return 0
	}
	ipv4 := ipNet.To4()
	if ipv4 == nil {
		return 0
	}
	return uint32(ipv4[0])<<24 + uint32(ipv4[1])<<16 + uint32(ipv4[2])<<8 + uint32(ipv4[3])
}

// uint32ToIP 将uint32转换为IP地址字符串
func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>>8)&0xFF,
		ip&0xFF)
}

// parsePort 解析端口字符串
func parsePort(portStr string) uint16 {
	if port, err := strconv.Atoi(portStr); err == nil && port > 0 && port <= 65535 {
		return uint16(port)
	}
	return 0
}

// isFlannelRelated 检查是否与Flannel相关
func isFlannelRelated(labels map[string]string) bool {
	if labels == nil {
		return false
	}

	// 检查常见的Flannel标签
	flannelLabels := []string{
		"app=flannel",
		"k8s-app=flannel",
		"component=flannel",
		"tier=node",
	}

	for _, flannelLabel := range flannelLabels {
		parts := strings.Split(flannelLabel, "=")
		if len(parts) == 2 {
			if value, exists := labels[parts[0]]; exists && value == parts[1] {
				return true
			}
		}
	}

	return false
}
