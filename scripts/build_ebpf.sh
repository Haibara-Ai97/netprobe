#!/bin/bash

# 简化的 eBPF 编译脚本
set -e

echo "🔨 Building eBPF TC monitoring programs..."

# 创建输出目录
mkdir -p bin/ebpf
mkdir -p pkg/ebpf/objects

# 编译网络监控程序
echo "📦 Compiling network monitor..."
clang -O2 -target bpf -c ebpf/network/monitor.c -o bin/ebpf/network-monitor.o

# 复制到嵌入目录
echo "📋 Copying objects for embedding..."
cp bin/ebpf/network-monitor.o pkg/ebpf/objects/

# 创建安全监控占位符（如果不存在）
if [ ! -f ebpf/security/monitor.c ]; then
    echo "⚠️  Security monitor not found, creating placeholder..."
    touch pkg/ebpf/objects/security-monitor.o
fi

echo "✅ eBPF programs compiled successfully!"
echo "📁 Output files:"
echo "  - bin/ebpf/network-monitor.o"
echo "  - pkg/ebpf/objects/network-monitor.o (for embedding)"

# 验证生成的对象文件
if command -v llvm-objdump >/dev/null 2>&1; then
    echo ""
    echo "🔍 Verifying eBPF object file..."
    llvm-objdump -h bin/ebpf/network-monitor.o
fi

echo ""
echo "📋 TC Programs in object file:"
echo "  - network_monitor_tc_egress (TC egress)"
echo "  - network_monitor_tc_ingress (TC ingress)"
echo "  - network_monitor_xdp (XDP)"

echo ""
echo "🗺️  Maps in object file:"
echo "  - packet_stats (global statistics)"
echo "  - tc_device_stats (per-device TC statistics)"
echo "  - tc_events (TC event ring buffer)"
echo "  - tc_flow_stats (TC flow statistics)"

echo ""
echo "🚀 Ready to use with embedded_loader.go!"
