package ebpf

import (
	"context"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/Haibara-Ai97/netprobe/ebpf/netfilter"
)

// NetfilterLoader eBPF Netfilter监控程序加载器
type NetfilterLoader struct {
	objs          netfilter.NetfilterMonitorObjects
	links         []link.Link
	ringbufReader *ringbuf.Reader
	handlers      []EventHandler
	ctx           context.Context
	cancel        context.CancelFunc
	mutex         sync.RWMutex
	isRunning     bool
}

// NewNetfilterLoader 创建Netfilter加载器
func NewNetfilterLoader() *NetfilterLoader {
	return &NetfilterLoader{
		handlers: make([]EventHandler, 0),
	}
}

// LoadPrograms 加载eBPF程序
func (nl *NetfilterLoader) LoadPrograms() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock limit: %w", err)
	}

	if err := netfilter.LoadNetfilterMonitorObjects(&nl.objs, nil); err != nil {
		return fmt.Errorf("loading netfilter monitor objects: %w", err)
	}

	fmt.Println("✅ Successfully loaded Netfilter eBPF programs")
	return nil
}

// AttachNetfilterHooks 附加Netfilter钩子
func (nl *NetfilterLoader) AttachNetfilterHooks() error {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	// 附加Netfilter程序
	l, err := link.AttachNetfilter(link.NetfilterOptions{
		Program:  nl.objs.NetfilterPrerouting,
		Priority: 0,
	})
	if err != nil {
		return fmt.Errorf("attaching netfilter hook: %w", err)
	}
	nl.links = append(nl.links, l)
	fmt.Println("✅ Netfilter prerouting hook attached")

	return nil
}

// InitializeRingBuffer 初始化Ring Buffer
func (nl *NetfilterLoader) InitializeRingBuffer(ctx context.Context) error {
	nl.ctx, nl.cancel = context.WithCancel(ctx)

	reader, err := ringbuf.NewReader(nl.objs.NetfilterEvents)
	if err != nil {
		return fmt.Errorf("creating netfilter ring buffer reader: %w", err)
	}
	nl.ringbufReader = reader

	fmt.Println("✅ Netfilter Ring Buffer initialized")
	return nil
}

// StartEventProcessing 开始事件处理
func (nl *NetfilterLoader) StartEventProcessing() error {
	if nl.ringbufReader == nil {
		return fmt.Errorf("ring buffer not initialized")
	}

	nl.isRunning = true

	go func() {
		defer nl.ringbufReader.Close()

		for {
			select {
			case <-nl.ctx.Done():
				return
			default:
				record, err := nl.ringbufReader.Read()
				if err != nil {
					if nl.isRunning {
						fmt.Printf("❌ Error reading from netfilter ring buffer: %v\n", err)
					}
					return
				}

				if len(record.RawSample) >= 36 { // NetworkEvent size
					event := (*NetworkEvent)(unsafe.Pointer(&record.RawSample[0]))

					// 确保这是Netfilter事件
					event.HookPoint = uint8(HookNetfilter)

					// 分发给所有处理器
					nl.mutex.RLock()
					for _, handler := range nl.handlers {
						if nl.handlerSupportsHook(handler, HookNetfilter) {
							go handler.HandleEvent(event)
						}
					}
					nl.mutex.RUnlock()
				}
			}
		}
	}()

	fmt.Println("✅ Netfilter event processing started")
	return nil
}

// AddEventHandler 添加事件处理器
func (nl *NetfilterLoader) AddEventHandler(handler EventHandler) {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()
	nl.handlers = append(nl.handlers, handler)
}

// handlerSupportsHook 检查处理器是否支持指定的钩子点
func (nl *NetfilterLoader) handlerSupportsHook(handler EventHandler, hook HookPoint) bool {
	supportedHooks := handler.GetSupportedHooks()
	for _, supportedHook := range supportedHooks {
		if supportedHook == hook {
			return true
		}
	}
	return false
}

// DetachNetfilterHooks 分离Netfilter钩子
func (nl *NetfilterLoader) DetachNetfilterHooks() error {
	nl.mutex.Lock()
	defer nl.mutex.Unlock()

	for _, l := range nl.links {
		if err := l.Close(); err != nil {
			return fmt.Errorf("closing netfilter link: %w", err)
		}
	}
	nl.links = nil

	fmt.Println("✅ Netfilter hooks detached")
	return nil
}

// Close 关闭加载器
func (nl *NetfilterLoader) Close() error {
	nl.isRunning = false

	if nl.cancel != nil {
		nl.cancel()
	}

	if err := nl.DetachNetfilterHooks(); err != nil {
		return err
	}

	if nl.ringbufReader != nil {
		nl.ringbufReader.Close()
	}

	nl.objs.Close()
	fmt.Println("✅ Netfilter loader closed")
	return nil
}

// GetStats 获取统计信息
func (nl *NetfilterLoader) GetStats() (map[string]uint64, error) {
	stats := make(map[string]uint64)

	// 从Map中读取统计信息
	if nl.objs.NetfilterStats != nil {
		var key uint32 = 0
		var value uint64
		if err := nl.objs.NetfilterStats.Lookup(&key, &value); err == nil {
			stats["netfilter_packets"] = value
		}

		key = 1
		if err := nl.objs.NetfilterStats.Lookup(&key, &value); err == nil {
			stats["netfilter_bytes"] = value
		}
	}

	return stats, nil
}
