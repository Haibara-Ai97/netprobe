#!/bin/bash

# eBPF 编译测试脚本
set -e

echo "🧪 Testing eBPF compilation..."

# 创建输出目录
mkdir -p bin/ebpf
mkdir -p pkg/ebpf/objects

# 测试不同的编译选项
echo ""
echo "📋 Testing different compilation approaches:"

# 1. 测试最简单的编译
echo "1️⃣  Testing minimal compilation..."
if clang -O2 -target bpf -c ebpf/network/monitor_fixed.c -o bin/test1.o 2>/dev/null; then
    echo "   ✅ Minimal compilation: SUCCESS"
    rm -f bin/test1.o
else
    echo "   ❌ Minimal compilation: FAILED"
fi

# 2. 测试带基本参数的编译
echo "2️⃣  Testing basic compilation..."
if clang -O2 -Wall -target bpf -c ebpf/network/monitor_fixed.c -o bin/test2.o 2>/dev/null; then
    echo "   ✅ Basic compilation: SUCCESS"
    rm -f bin/test2.o
else
    echo "   ❌ Basic compilation: FAILED"
fi

# 3. 测试完整参数的编译
echo "3️⃣  Testing full compilation..."
CLANG_FLAGS="-O2 -g -Wall -Werror \
    -D__KERNEL__ -D__BPF_TRACING__ \
    -Wno-unused-value -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-address-of-packed-member \
    -I/usr/include \
    -I/usr/include/$(uname -m)-linux-gnu"

if clang $CLANG_FLAGS -target bpf -c ebpf/network/monitor_fixed.c -o bin/test3.o 2>/dev/null; then
    echo "   ✅ Full compilation: SUCCESS"
    rm -f bin/test3.o
else
    echo "   ❌ Full compilation: FAILED"
fi

# 4. 测试标准版本编译
echo "4️⃣  Testing standard version..."
if [ -f "ebpf/network/monitor.c" ]; then
    if clang -O2 -target bpf -c ebpf/network/monitor.c -o bin/test4.o 2>/dev/null; then
        echo "   ✅ Standard version: SUCCESS"
        rm -f bin/test4.o
    else
        echo "   ❌ Standard version: FAILED"
    fi
else
    echo "   ⚠️  Standard version: FILE NOT FOUND"
fi

echo ""
echo "🎯 Recommended compilation command:"
echo "clang -O2 -target bpf -c ebpf/network/monitor_fixed.c -o bin/ebpf/network-monitor.o"

echo ""
echo "🚀 Run this to build:"
echo "make build-ebpf-minimal"
