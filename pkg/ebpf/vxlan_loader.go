package ebpf

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Haibara-Ai97/netprobe/ebpf/vxlan"
)

// VxlanFlowKey VXLAN流量标识
type VxlanFlowKey struct {
	OuterSrcIP   uint32   // 外层源IP (宿主机IP)
	OuterDstIP   uint32   // 外层目标IP (宿主机IP)
	InnerSrcIP   uint32   // 内层源IP (Pod IP)
	InnerDstIP   uint32   // 内层目标IP (Pod IP)
	VNI          uint32   // VXLAN网络标识符
	InnerSrcPort uint16   // 内层源端口
	InnerDstPort uint16   // 内层目标端口
	InnerProto   uint8    // 内层协议
	Direction    uint8    // 流量方向: 0=ingress, 1=egress
	_            [2]uint8 // 填充对齐
}

// VxlanFlowStats VXLAN流量统计
type VxlanFlowStats struct {
	Packets      uint64 // 数据包数量
	Bytes        uint64 // 字节数
	FirstSeen    uint64 // 首次观察时间
	LastSeen     uint64 // 最后观察时间
	EncapPackets uint32 // 封装数据包数
	DecapPackets uint32 // 解封装数据包数
	EncapBytes   uint64 // 封装字节数
	DecapBytes   uint64 // 解封装字节数
}

// VxlanEvent VXLAN事件
type VxlanEvent struct {
	Timestamp    uint64   // 事件时间戳
	OuterSrcIP   uint32   // 外层源IP
	OuterDstIP   uint32   // 外层目标IP
	InnerSrcIP   uint32   // 内层源IP
	InnerDstIP   uint32   // 内层目标IP
	VNI          uint32   // VXLAN网络标识符
	InnerSrcPort uint16   // 内层源端口
	InnerDstPort uint16   // 内层目标端口
	PacketLen    uint16   // 数据包长度
	InnerProto   uint8    // 内层协议
	Direction    uint8    // 流量方向
	EventType    uint8    // 事件类型: 0=正常, 1=新建连接, 2=异常
	VxlanFlags   uint8    // VXLAN标志位
	HookPoint    uint8    // Hook点: 2=TC_INGRESS, 3=TC_EGRESS
	_            [3]uint8 // 填充对齐
	Ifindex      uint32   // 网络接口索引
}

// PodInfo Pod信息
type PodInfo struct {
	NodeIP      uint32   // 节点IP地址
	VNI         uint32   // 所属VXLAN网络
	PodName     [64]int8 // Pod名称
	Namespace   [32]int8 // 命名空间
	CreatedTime uint64   // 创建时间
}

// BasicStats 基础统计信息
type BasicStats struct {
	Packets uint64 // 数据包数量
	Bytes   uint64 // 字节数
	Errors  uint64 // 错误数
	Drops   uint64 // 丢弃数
}

// VxlanLoader VXLAN监控加载器
type VxlanLoader struct {
	objs           *vxlan.VxlanMonitorObjects
	ingressLink    link.Link
	egressLink     link.Link
	reader         *ringbuf.Reader
	eventHandler   VxlanEventHandler
	ctx            context.Context
	cancel         context.CancelFunc
	interfaceName  string
	interfaceIndex int
	isLoaded       bool
	statsInterval  time.Duration
}

// VxlanEventHandler VXLAN事件处理器接口
type VxlanEventHandler interface {
	HandleVxlanEvent(event *VxlanEvent)
	HandleVxlanStats(stats map[VxlanFlowKey]VxlanFlowStats)
	HandleError(err error)
}

// DefaultVxlanEventHandler 默认VXLAN事件处理器
type DefaultVxlanEventHandler struct{}

func (h *DefaultVxlanEventHandler) HandleVxlanEvent(event *VxlanEvent) {
	log.Printf("VXLAN Event: VNI=%d, %s:%d -> %s:%d, Proto=%d, Direction=%d, Size=%d bytes",
		event.VNI,
		intToIP(event.InnerSrcIP), event.InnerSrcPort,
		intToIP(event.InnerDstIP), event.InnerDstPort,
		event.InnerProto, event.Direction, event.PacketLen)
}

func (h *DefaultVxlanEventHandler) HandleVxlanStats(stats map[VxlanFlowKey]VxlanFlowStats) {
	log.Printf("VXLAN Stats Update: %d active flows", len(stats))
}

func (h *DefaultVxlanEventHandler) HandleError(err error) {
	log.Printf("VXLAN Error: %v", err)
}

// NewVxlanLoader 创建新的VXLAN监控加载器
func NewVxlanLoader(interfaceName string) (*VxlanLoader, error) {
	// 移除内存限制
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock: %v", err)
	}

	// 获取网络接口信息
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	loader := &VxlanLoader{
		interfaceName:  interfaceName,
		interfaceIndex: iface.Index,
		ctx:            ctx,
		cancel:         cancel,
		eventHandler:   &DefaultVxlanEventHandler{},
		statsInterval:  30 * time.Second,
	}

	return loader, nil
}

// SetEventHandler 设置事件处理器
func (vl *VxlanLoader) SetEventHandler(handler VxlanEventHandler) {
	vl.eventHandler = handler
}

// SetStatsInterval 设置统计报告间隔
func (vl *VxlanLoader) SetStatsInterval(interval time.Duration) {
	vl.statsInterval = interval
}

// Load 加载VXLAN eBPF程序
func (vl *VxlanLoader) Load() error {
	if vl.isLoaded {
		return fmt.Errorf("VXLAN loader already loaded")
	}

	// 加载eBPF程序和映射
	objs := vxlan.VxlanMonitorObjects{}
	if err := vxlan.LoadVxlanMonitorObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load VXLAN eBPF objects: %v", err)
	}
	vl.objs = &objs

	// 附加TC ingress程序
	if err := vl.attachTCProgram(true); err != nil {
		vl.Close()
		return fmt.Errorf("failed to attach TC ingress program: %v", err)
	}

	// 附加TC egress程序
	if err := vl.attachTCProgram(false); err != nil {
		vl.Close()
		return fmt.Errorf("failed to attach TC egress program: %v", err)
	}

	// 设置Ring Buffer读取器
	reader, err := ringbuf.NewReader(vl.objs.VxlanEvents)
	if err != nil {
		vl.Close()
		return fmt.Errorf("failed to create ring buffer reader: %v", err)
	}
	vl.reader = reader

	vl.isLoaded = true

	// 启动事件处理协程
	go vl.handleEvents()
	go vl.reportStats()

	log.Printf("VXLAN monitor loaded on interface %s (index: %d)",
		vl.interfaceName, vl.interfaceIndex)
	return nil
}

// attachTCProgram 附加TC程序 (简化版本)
func (vl *VxlanLoader) attachTCProgram(isIngress bool) error {
	// 选择程序和方向
	var prog *ebpf.Program
	var direction string
	if isIngress {
		prog = vl.objs.VxlanIngressMonitor
		direction = "ingress"
	} else {
		prog = vl.objs.VxlanEgressMonitor
		direction = "egress"
	}

	// 创建TC链接 (这是一个简化的实现，实际环境中可能需要更复杂的TC管理)
	// 这里我们只记录程序已加载，实际的TC附加需要外部工具配合
	log.Printf("VXLAN TC %s program loaded (FD: %d) for interface %s",
		direction, prog.FD(), vl.interfaceName)

	// 注意：实际的TC附加需要使用系统命令或专门的TC库
	// 这里为了演示，我们只是加载了程序，需要手动使用tc命令附加

	return nil
}

// handleEvents 处理Ring Buffer事件
func (vl *VxlanLoader) handleEvents() {
	defer vl.reader.Close()

	for {
		select {
		case <-vl.ctx.Done():
			return
		default:
			record, err := vl.reader.Read()
			if err != nil {
				if err != ringbuf.ErrClosed {
					vl.eventHandler.HandleError(fmt.Errorf("ring buffer read error: %v", err))
				}
				continue
			}

			// 解析事件数据
			if len(record.RawSample) >= int(unsafe.Sizeof(VxlanEvent{})) {
				event := (*VxlanEvent)(unsafe.Pointer(&record.RawSample[0]))
				vl.eventHandler.HandleVxlanEvent(event)
			}
		}
	}
}

// reportStats 定期报告统计信息
func (vl *VxlanLoader) reportStats() {
	ticker := time.NewTicker(vl.statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-vl.ctx.Done():
			return
		case <-ticker.C:
			stats, err := vl.GetFlowStats()
			if err != nil {
				vl.eventHandler.HandleError(fmt.Errorf("failed to get flow stats: %v", err))
				continue
			}
			vl.eventHandler.HandleVxlanStats(stats)
		}
	}
}

// GetFlowStats 获取VXLAN流量统计
func (vl *VxlanLoader) GetFlowStats() (map[VxlanFlowKey]VxlanFlowStats, error) {
	if !vl.isLoaded {
		return nil, fmt.Errorf("VXLAN loader not loaded")
	}

	stats := make(map[VxlanFlowKey]VxlanFlowStats)

	// 遍历流量统计映射
	var key VxlanFlowKey
	var value VxlanFlowStats
	iter := vl.objs.VxlanFlowStats.Iterate()

	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate flow stats: %v", err)
	}

	return stats, nil
}

// GetInterfaceStats 获取接口VXLAN统计
func (vl *VxlanLoader) GetInterfaceStats() (map[uint32]BasicStats, error) {
	if !vl.isLoaded {
		return nil, fmt.Errorf("VXLAN loader not loaded")
	}

	stats := make(map[uint32]BasicStats)

	var key uint32
	var value BasicStats
	iter := vl.objs.VxlanInterfaceStats.Iterate()

	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate interface stats: %v", err)
	}

	return stats, nil
}

// GetNetworkStats 获取VXLAN网络统计
func (vl *VxlanLoader) GetNetworkStats() (map[uint32]BasicStats, error) {
	if !vl.isLoaded {
		return nil, fmt.Errorf("VXLAN loader not loaded")
	}

	stats := make(map[uint32]BasicStats)

	var key uint32
	var value BasicStats
	iter := vl.objs.VxlanNetworkStats.Iterate()

	for iter.Next(&key, &value) {
		stats[key] = value
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate network stats: %v", err)
	}

	return stats, nil
}

// AddPodInfo 添加Pod信息
func (vl *VxlanLoader) AddPodInfo(podIP uint32, nodeIP uint32, vni uint32,
	podName, namespace string) error {
	if !vl.isLoaded {
		return fmt.Errorf("VXLAN loader not loaded")
	}

	key := struct{ PodIP uint32 }{PodIP: podIP}

	info := PodInfo{
		NodeIP:      nodeIP,
		VNI:         vni,
		CreatedTime: uint64(time.Now().UnixNano()),
	}

	// 复制字符串到固定长度数组
	copy((*[64]byte)(unsafe.Pointer(&info.PodName))[:], podName)
	copy((*[32]byte)(unsafe.Pointer(&info.Namespace))[:], namespace)

	if err := vl.objs.PodInfoMap.Put(key, info); err != nil {
		return fmt.Errorf("failed to add pod info: %v", err)
	}

	return nil
}

// RemovePodInfo 移除Pod信息
func (vl *VxlanLoader) RemovePodInfo(podIP uint32) error {
	if !vl.isLoaded {
		return fmt.Errorf("VXLAN loader not loaded")
	}

	key := struct{ PodIP uint32 }{PodIP: podIP}

	if err := vl.objs.PodInfoMap.Delete(key); err != nil {
		return fmt.Errorf("failed to remove pod info: %v", err)
	}

	return nil
}

// Close 关闭VXLAN监控加载器
func (vl *VxlanLoader) Close() error {
	if !vl.isLoaded {
		return nil
	}

	vl.cancel()

	if vl.reader != nil {
		vl.reader.Close()
	}

	if vl.ingressLink != nil {
		vl.ingressLink.Close()
	}

	if vl.egressLink != nil {
		vl.egressLink.Close()
	}

	if vl.objs != nil {
		vl.objs.Close()
	}

	vl.isLoaded = false
	log.Printf("VXLAN monitor closed for interface %s", vl.interfaceName)
	return nil
}
