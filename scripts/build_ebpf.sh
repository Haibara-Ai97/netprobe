#!/bin/bash

# NetProbe eBPF 编译脚本 - 增强版
# 支持编译网络监控、Socket 监控和 Netfilter 监控程序
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🔨 Building NetProbe eBPF programs..."

# 检查依赖
check_dependencies() {
    log_info "检查编译依赖..."
    
    if ! command -v clang >/dev/null 2>&1; then
        log_error "clang not found. Please install clang."
        exit 1
    fi
    
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go not found. Please install Go."
        exit 1
    fi
    
    # 检查内核头文件
    if [ ! -d "/usr/include/linux" ] && [ ! -d "/usr/src/linux-headers-$(uname -r)" ]; then
        log_warn "Linux kernel headers not found."
        log_info "Please install kernel headers:"
        echo "  Ubuntu/Debian: sudo apt-get install linux-headers-\$(uname -r)"
        echo "  CentOS/RHEL: sudo yum install kernel-devel"
    fi
    
    log_success "依赖检查完成"
}

check_dependencies

# 创建输出目录
mkdir -p bin/ebpf
mkdir -p pkg/ebpf/objects
mkdir -p ebpf/include

# 编译参数
CLANG_FLAGS="-O2 -g -Wall -Werror \
    -D__KERNEL__ -D__BPF_TRACING__ \
    -Wno-unused-value -Wno-pointer-sign \
    -Wno-compare-distinct-pointer-types \
    -Wno-address-of-packed-member \
    -I/usr/include \
    -I./ebpf/include \
    -I/usr/include/$(uname -m)-linux-gnu"

# 使用 bpf2go 的编译方法
compile_with_bpf2go() {
    local dir=$1
    local name=$2
    
    log_info "使用 bpf2go 编译 $name..."
    
    cd "ebpf/$dir"
    if go generate; then
        log_success "$name 编译成功 (bpf2go)"
        cd - > /dev/null
        return 0
    else
        log_warn "$name bpf2go 编译失败，尝试直接编译"
        cd - > /dev/null
        return 1
    fi
}

# 直接编译方法
compile_direct() {
    local source=$1
    local output=$2
    local name=$3
    
    log_info "直接编译 $name..."
    
    if clang $CLANG_FLAGS -target bpf -c "$source" -o "$output" 2>/dev/null; then
        log_success "$name 直接编译成功"
        return 0
    elif clang -O2 -target bpf -c "$source" -o "$output" 2>/dev/null; then
        log_success "$name 简化编译成功"
        return 0
    else
        log_error "$name 编译失败"
        return 1
    fi
}

# 编译程序列表
programs=(
    "network:NetworkMonitor:network-monitor.o"
    "socket:SocketMonitor:socket-monitor.o"
    "netfilter:NetfilterMonitor:netfilter-monitor.o"
)

# 编译所有程序
failed_count=0
success_count=0

for program in "${programs[@]}"; do
    IFS=':' read -r dir name output <<< "$program"
    
    log_info "开始编译 $name 程序..."
    
    # 检查源文件是否存在
    if [ ! -f "ebpf/$dir/monitor.c" ]; then
        log_warn "$dir/monitor.c 不存在，跳过"
        continue
    fi
    
    # 优先尝试 bpf2go 方法
    if compile_with_bpf2go "$dir" "$name"; then
        ((success_count++))
    # 如果 bpf2go 失败，尝试直接编译
    elif compile_direct "ebpf/$dir/monitor.c" "bin/ebpf/$output" "$name"; then
        # 复制到嵌入目录
        cp "bin/ebpf/$output" pkg/ebpf/objects/
        ((success_count++))
    else
        ((failed_count++))
    fi
    
    echo ""
done

# 特殊处理网络监控程序（保持向后兼容）
log_info "编译传统网络监控程序..."
if [ -f "ebpf/network/monitor.c" ]; then
    if compile_direct "ebpf/network/monitor.c" "bin/ebpf/network-monitor.o" "Legacy Network Monitor"; then
        cp bin/ebpf/network-monitor.o pkg/ebpf/objects/
        log_success "传统网络监控程序编译完成"
    fi
fi

# 输出编译结果
echo ""
log_info "编译完成！"
log_info "成功: $success_count 个程序"

if [ $failed_count -gt 0 ]; then
    log_error "失败: $failed_count 个程序"
else
    log_success "所有 eBPF 程序编译成功！"
fi

# 显示生成的文件
echo ""
log_info "生成的文件:"
if [ -d "bin/ebpf" ]; then
    ls -la bin/ebpf/
fi

if [ -d "pkg/ebpf/objects" ]; then
    echo ""
    log_info "嵌入对象文件:"
    ls -la pkg/ebpf/objects/
fi

# 检查生成的 Go 文件
echo ""
log_info "生成的 Go 绑定文件:"
find ebpf/ -name "*_bpfel.go" -o -name "*_bpfeb.go" 2>/dev/null | head -10

echo ""
log_success "🎉 NetProbe eBPF 编译完成！"
echo ""
log_info "使用说明:"
echo "1. 运行程序需要 root 权限或 CAP_BPF 权限"
echo "2. 确保内核支持所需的 eBPF 功能"
echo "3. 在 Go 代码中导入生成的包进行使用"
echo "4. Socket 监控支持 TCP/UDP 连接跟踪"
echo "5. Netfilter 监控支持防火墙规则和包过滤"
echo "6. 网络监控支持 XDP 高性能包处理和 DDoS 防护"
