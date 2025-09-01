package ebpf

import (
	"context"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Haibara-Ai97/netprobe/ebpf/socket"
)

// SocketLoader eBPF Socket监控程序加载器
type SocketLoader struct {
	objs          socket.SocketMonitorObjects
	links         []link.Link
	ringbufReader *ringbuf.Reader
	handlers      []EventHandler
	ctx           context.Context
	cancel        context.CancelFunc
	mutex         sync.RWMutex
	isRunning     bool
}

// NewSocketLoader 创建Socket加载器
func NewSocketLoader() *SocketLoader {
	return &SocketLoader{
		handlers: make([]EventHandler, 0),
	}
}

// LoadPrograms 加载eBPF程序
func (sl *SocketLoader) LoadPrograms() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock limit: %w", err)
	}

	if err := socket.LoadSocketMonitorObjects(&sl.objs, nil); err != nil {
		return fmt.Errorf("loading socket monitor objects: %w", err)
	}

	fmt.Println("✅ Successfully loaded Socket eBPF programs")
	return nil
}

// AttachSocketPrograms 附加Socket程序
func (sl *SocketLoader) AttachSocketPrograms() error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	// 附加TraceSocketCreate程序 (tracepoint)
	if sl.objs.TraceSocketCreate != nil {
		l, err := link.Tracepoint("syscalls", "sys_enter_socket", sl.objs.TraceSocketCreate, nil)
		if err != nil {
			return fmt.Errorf("attaching trace_socket_create tracepoint: %w", err)
		}
		sl.links = append(sl.links, l)
		fmt.Println("✅ Socket tracepoint attached")
	}

	return nil
}

// InitializeRingBuffer 初始化Ring Buffer
func (sl *SocketLoader) InitializeRingBuffer(ctx context.Context) error {
	sl.ctx, sl.cancel = context.WithCancel(ctx)

	reader, err := ringbuf.NewReader(sl.objs.SocketEvents)
	if err != nil {
		return fmt.Errorf("creating socket ring buffer reader: %w", err)
	}
	sl.ringbufReader = reader

	fmt.Println("✅ Socket Ring Buffer initialized")
	return nil
}

// StartEventProcessing 开始事件处理
func (sl *SocketLoader) StartEventProcessing() error {
	if sl.ringbufReader == nil {
		return fmt.Errorf("ring buffer not initialized")
	}

	sl.isRunning = true

	go func() {
		defer sl.ringbufReader.Close()

		for {
			select {
			case <-sl.ctx.Done():
				return
			default:
				record, err := sl.ringbufReader.Read()
				if err != nil {
					if sl.isRunning {
						fmt.Printf("❌ Error reading from socket ring buffer: %v\n", err)
					}
					return
				}

				if len(record.RawSample) >= 72 { // SocketEvent size
					socketEvent := (*SocketEvent)(unsafe.Pointer(&record.RawSample[0]))

					// 转换为通用的NetworkEvent格式以兼容现有处理器
					networkEvent := &NetworkEvent{
						Timestamp: socketEvent.Timestamp,
						SrcIP:     socketEvent.SrcIP,
						DstIP:     socketEvent.DstIP,
						SrcPort:   socketEvent.SrcPort,
						DstPort:   socketEvent.DstPort,
						PacketLen: uint16(socketEvent.BytesSent + socketEvent.BytesRecv),
						Protocol:  socketEvent.Protocol,
						Direction: 0, // Socket事件不区分方向
						TCPFlags:  0, // Socket事件暂不处理TCP标志位
						EventType: uint8(socketEvent.EventType),
						HookPoint: uint8(HookSocket),
						Ifindex:   0, // Socket事件不涉及网络接口
					}

					// 分发给所有处理器
					sl.mutex.RLock()
					for _, handler := range sl.handlers {
						if sl.handlerSupportsHook(handler, HookSocket) {
							go handler.HandleEvent(networkEvent)
						}
					}
					sl.mutex.RUnlock()
				}
			}
		}
	}()

	fmt.Println("✅ Socket event processing started")
	return nil
}

// AddEventHandler 添加事件处理器
func (sl *SocketLoader) AddEventHandler(handler EventHandler) {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()
	sl.handlers = append(sl.handlers, handler)
}

// handlerSupportsHook 检查处理器是否支持指定的钩子点
func (sl *SocketLoader) handlerSupportsHook(handler EventHandler, hook HookPoint) bool {
	supportedHooks := handler.GetSupportedHooks()
	for _, supportedHook := range supportedHooks {
		if supportedHook == hook {
			return true
		}
	}
	return false
}

// DetachSocketPrograms 分离Socket程序
func (sl *SocketLoader) DetachSocketPrograms() error {
	sl.mutex.Lock()
	defer sl.mutex.Unlock()

	for _, l := range sl.links {
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing socket link: %w", err)
		}
	}
	sl.links = nil

	fmt.Println("✅ Socket programs detached")
	return nil
}

// Close 关闭加载器
func (sl *SocketLoader) Close() error {
	sl.isRunning = false

	if sl.cancel != nil {
		sl.cancel()
	}

	if err := sl.DetachSocketPrograms(); err != nil {
		return err
	}

	if sl.ringbufReader != nil {
		sl.ringbufReader.Close()
	}

	sl.objs.Close()
	fmt.Println("✅ Socket loader closed")
	return nil
}

// GetStats 获取统计信息
func (sl *SocketLoader) GetStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	// 从Map中读取统计信息
	if sl.objs.SocketStats != nil {
		var key uint32 = 0
		var value uint64
		if err := sl.objs.SocketStats.Lookup(&key, &value); err == nil {
			stats["socket_packets"] = value
		}

		key = 1
		if err := sl.objs.SocketStats.Lookup(&key, &value); err == nil {
			stats["socket_bytes"] = value
		}
	}

	return stats, nil
}

// AddSocketToMonitor 添加Socket到监控
func (sl *SocketLoader) AddSocketToMonitor(socketID uint64) error {
	if sl.objs.SocketConnections == nil {
		return fmt.Errorf("socket_connections map not available")
	}

	// 创建一个空的连接信息结构体作为占位符
	var connInfo SocketConnInfo
	if err := sl.objs.SocketConnections.Update(&socketID, &connInfo, 0); err != nil {
		return fmt.Errorf("adding socket to monitor: %w", err)
	}

	fmt.Printf("✅ Socket %d added to monitoring\n", socketID)
	return nil
}

// RemoveSocketFromMonitor 从监控中移除Socket
func (sl *SocketLoader) RemoveSocketFromMonitor(socketID uint64) error {
	if sl.objs.SocketConnections == nil {
		return fmt.Errorf("socket_connections map not available")
	}

	if err := sl.objs.SocketConnections.Delete(&socketID); err != nil {
		return fmt.Errorf("removing socket from monitor: %w", err)
	}

	fmt.Printf("✅ Socket %d removed from monitoring\n", socketID)
	return nil
}

// GetMonitoredSockets 获取被监控的Socket列表
func (sl *SocketLoader) GetMonitoredSockets() ([]uint64, error) {
	if sl.objs.SocketConnections == nil {
		return nil, fmt.Errorf("socket_connections map not available")
	}

	var sockets []uint64
	iter := sl.objs.SocketConnections.Iterate()
	var key uint64
	var value SocketConnInfo

	for iter.Next(&key, &value) {
		sockets = append(sockets, key)
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating monitored sockets: %w", err)
	}

	return sockets, nil
}

// GetSocketConnectionInfo 获取Socket连接信息
func (sl *SocketLoader) GetSocketConnectionInfo(socketID uint64) (*SocketConnInfo, error) {
	if sl.objs.SocketConnections == nil {
		return nil, fmt.Errorf("socket_connections map not available")
	}

	var connInfo SocketConnInfo
	if err := sl.objs.SocketConnections.Lookup(&socketID, &connInfo); err != nil {
		return nil, fmt.Errorf("looking up socket connection info: %w", err)
	}

	return &connInfo, nil
}
