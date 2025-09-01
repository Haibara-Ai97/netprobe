package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
)

// HTTPServer HTTP服务器，提供REST API
type HTTPServer struct {
	integrator *K8sNetworkIntegrator
	server     *http.Server
	port       int
}

// NewHTTPServer 创建HTTP服务器
func NewHTTPServer(integrator *K8sNetworkIntegrator, port int) *HTTPServer {
	return &HTTPServer{
		integrator: integrator,
		port:       port,
	}
}

// Start 启动HTTP服务器
func (s *HTTPServer) Start() error {
	mux := http.NewServeMux()

	// 注册路由
	mux.HandleFunc("/api/cluster", s.handleClusterInfo)
	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/flannel", s.handleFlannelTopology)
	mux.HandleFunc("/api/stats", s.handleTrafficStats)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/query/pod", s.handleQueryPod)
	mux.HandleFunc("/api/query/service", s.handleQueryService)
	mux.HandleFunc("/api/query/node", s.handleQueryNode)
	mux.HandleFunc("/api/report", s.handleNetworkReport)
	mux.HandleFunc("/health", s.handleHealth)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: s.addCORSHeaders(mux),
	}

	klog.InfoS("Starting HTTP server", "port", s.port)
	return s.server.ListenAndServe()
}

// Stop 停止HTTP服务器
func (s *HTTPServer) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// addCORSHeaders 添加CORS头
func (s *HTTPServer) addCORSHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// 处理集群信息请求
func (s *HTTPServer) handleClusterInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.integrator.GetClusterInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, info)
}

// 处理拓扑信息请求
func (s *HTTPServer) handleTopology(w http.ResponseWriter, r *http.Request) {
	topology := s.integrator.GetTopology()
	s.writeJSON(w, topology)
}

// 处理Flannel拓扑请求
func (s *HTTPServer) handleFlannelTopology(w http.ResponseWriter, r *http.Request) {
	topology := s.integrator.GetFlannelTopology()
	s.writeJSON(w, topology)
}

// 处理流量统计请求
func (s *HTTPServer) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	stats := s.integrator.GetTrafficStats()
	s.writeJSON(w, stats)
}

// 处理流量查询请求
func (s *HTTPServer) handleFlows(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()

	direction := params.Get("direction")
	namespace := params.Get("namespace")
	node := params.Get("node")

	var flows []*TrafficFlow

	if direction != "" {
		flows = s.integrator.GetFlowsByDirection(direction)
	} else if namespace != "" {
		flows = s.integrator.GetFlowsByNamespace(namespace)
	} else if node != "" {
		flows = s.integrator.GetFlowsByNode(node)
	} else {
		// 返回top talkers
		limit := 50
		if l := params.Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		talkers := s.integrator.GetTopTalkers(limit)
		s.writeJSON(w, talkers)
		return
	}

	s.writeJSON(w, flows)
}

// 处理Pod查询请求
func (s *HTTPServer) handleQueryPod(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip parameter required", http.StatusBadRequest)
		return
	}

	pod := s.integrator.QueryPodByIP(ip)
	if pod == nil {
		http.Error(w, "pod not found", http.StatusNotFound)
		return
	}

	s.writeJSON(w, pod)
}

// 处理Service查询请求
func (s *HTTPServer) handleQueryService(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip parameter required", http.StatusBadRequest)
		return
	}

	service := s.integrator.QueryServiceByIP(ip)
	if service == nil {
		http.Error(w, "service not found", http.StatusNotFound)
		return
	}

	s.writeJSON(w, service)
}

// 处理Node查询请求
func (s *HTTPServer) handleQueryNode(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip parameter required", http.StatusBadRequest)
		return
	}

	node := s.integrator.QueryNodeByIP(ip)
	if node == nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	s.writeJSON(w, node)
}

// 处理网络报告请求
func (s *HTTPServer) handleNetworkReport(w http.ResponseWriter, r *http.Request) {
	report := s.integrator.GenerateNetworkReport()
	s.writeJSON(w, report)
}

// 处理健康检查请求
func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	}
	s.writeJSON(w, health)
}

// writeJSON 写入JSON响应
func (s *HTTPServer) writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		klog.ErrorS(err, "Failed to encode JSON response")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// GetPodEndpoints 获取Pod的所有端点
func GetPodEndpoints(client *Client, namespace, podName string) ([]EndpointInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	endpoints, err := client.clientset.CoreV1().Endpoints(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var result []EndpointInfo
	for _, ep := range endpoints.Items {
		epInfo := EndpointInfo{
			ServiceName: ep.Name,
			Namespace:   ep.Namespace,
			Subsets:     make([]EndpointSubset, len(ep.Subsets)),
		}

		for i, subset := range ep.Subsets {
			epSubset := EndpointSubset{
				Addresses: make([]EndpointAddress, len(subset.Addresses)),
				Ports:     make([]EndpointPort, len(subset.Ports)),
			}

			for j, addr := range subset.Addresses {
				epAddr := EndpointAddress{
					IP:       addr.IP,
					Hostname: addr.Hostname,
				}
				if addr.NodeName != nil {
					epAddr.NodeName = *addr.NodeName
				}
				if addr.TargetRef != nil && addr.TargetRef.Name == podName {
					epAddr.PodName = addr.TargetRef.Name
				}
				epSubset.Addresses[j] = epAddr
			}

			for j, port := range subset.Ports {
				epSubset.Ports[j] = EndpointPort{
					Name:     port.Name,
					Port:     port.Port,
					Protocol: string(port.Protocol),
				}
			}

			epInfo.Subsets[i] = epSubset
		}

		result = append(result, epInfo)
	}

	return result, nil
}

// ValidateIPAddress 验证IP地址
func ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ValidateCIDR 验证CIDR
func ValidateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsPrivateIP 检查是否为私有IP
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查常见的私有IP范围
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// GetFlannelAnnotations 获取Flannel相关的注解
func GetFlannelAnnotations(annotations map[string]string) map[string]string {
	flannelAnnotations := make(map[string]string)

	if annotations == nil {
		return flannelAnnotations
	}

	for key, value := range annotations {
		if strings.Contains(key, "flannel") ||
			strings.Contains(key, "backend") ||
			strings.Contains(key, "subnet") {
			flannelAnnotations[key] = value
		}
	}

	return flannelAnnotations
}

// FormatBytes 格式化字节数
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration 格式化持续时间
func FormatDuration(duration time.Duration) string {
	if duration < time.Minute {
		return fmt.Sprintf("%.1fs", duration.Seconds())
	} else if duration < time.Hour {
		return fmt.Sprintf("%.1fm", duration.Minutes())
	} else if duration < 24*time.Hour {
		return fmt.Sprintf("%.1fh", duration.Hours())
	} else {
		return fmt.Sprintf("%.1fd", duration.Hours()/24)
	}
}

// GetServiceType 获取服务类型描述
func GetServiceType(serviceType string) string {
	switch serviceType {
	case "ClusterIP":
		return "集群内部服务"
	case "NodePort":
		return "节点端口服务"
	case "LoadBalancer":
		return "负载均衡服务"
	case "ExternalName":
		return "外部名称服务"
	default:
		return "未知服务类型"
	}
}

// CalculateNetworkUtilization 计算网络利用率
func CalculateNetworkUtilization(stats *TrafficStats, timeWindow time.Duration) NetworkUtilization {
	return NetworkUtilization{
		TotalFlowsPerSecond:     float64(stats.TotalFlows) / timeWindow.Seconds(),
		IntraNodeFlowsPerSecond: float64(stats.IntraNodeFlows) / timeWindow.Seconds(),
		InterNodeFlowsPerSecond: float64(stats.InterNodeFlows) / timeWindow.Seconds(),
		VXLANFlowsPerSecond:     float64(stats.VXLANFlows) / timeWindow.Seconds(),
		TimeWindow:              timeWindow,
		LastCalculated:          time.Now(),
	}
}

// NetworkUtilization 网络利用率
type NetworkUtilization struct {
	TotalFlowsPerSecond     float64       `json:"total_flows_per_second"`
	IntraNodeFlowsPerSecond float64       `json:"intra_node_flows_per_second"`
	InterNodeFlowsPerSecond float64       `json:"inter_node_flows_per_second"`
	VXLANFlowsPerSecond     float64       `json:"vxlan_flows_per_second"`
	TimeWindow              time.Duration `json:"time_window"`
	LastCalculated          time.Time     `json:"last_calculated"`
}
