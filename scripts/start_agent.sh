#!/bin/bash

# NetProbe Agent 启动脚本

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [ "$DEBUG" = "1" ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."
    
    # 检查是否以 root 权限运行
    if [ "$EUID" -ne 0 ]; then
        log_error "请以 root 权限运行此脚本 (sudo)"
        exit 1
    fi
    
    # 检查 clang 和 llvm
    if ! command -v clang &> /dev/null; then
        log_error "clang 未安装，请安装 clang"
        exit 1
    fi
    
    # 检查内核版本
    KERNEL_VERSION=$(uname -r)
    log_info "内核版本: $KERNEL_VERSION"
    
    # 检查是否有 eBPF 支持
    if [ ! -f /proc/config.gz ] && [ ! -f /boot/config-$(uname -r) ]; then
        log_warn "无法检查内核配置，假设支持 eBPF"
    fi
}

# 编译 eBPF 程序
compile_ebpf() {
    log_info "编译 eBPF 程序..."
    
    cd /workspace/netprobe
    
    # 生成 eBPF 代码
    if [ -f "ebpf/network/monitor.c" ]; then
        log_info "生成网络监控 eBPF 代码..."
        cd ebpf/network
        go generate
        cd ../..
    else
        log_error "eBPF 源文件不存在"
        exit 1
    fi
}

# 构建 agent
build_agent() {
    log_info "构建 NetProbe Agent..."
    
    cd /workspace/netprobe
    go build -o bin/netprobe-agent ./cmd/agent/
    
    if [ $? -eq 0 ]; then
        log_info "Agent 构建成功"
    else
        log_error "Agent 构建失败"
        exit 1
    fi
}

# 启动 agent
start_agent() {
    log_info "启动 NetProbe Agent..."
    
    # 默认配置
    METRICS_PORT=${METRICS_PORT:-8081}
    COLLECT_INTERVAL=${COLLECT_INTERVAL:-5s}
    INTERFACE_FILTER=${INTERFACE_FILTER:-""}
    ACTIVE_ONLY=${ACTIVE_ONLY:-false}
    DEBUG=${DEBUG:-0}
    ATTACH_INTERFACE=${ATTACH_INTERFACE:-""}
    
    # 构建命令行参数
    ARGS="--metrics-port=$METRICS_PORT --collect-interval=$COLLECT_INTERVAL"
    
    if [ "$ACTIVE_ONLY" = "true" ]; then
        ARGS="$ARGS --active-only"
    fi
    
    if [ "$DEBUG" = "1" ]; then
        ARGS="$ARGS --debug"
    fi
    
    if [ -n "$INTERFACE_FILTER" ]; then
        for iface in $(echo $INTERFACE_FILTER | tr ',' ' '); do
            ARGS="$ARGS --interface-filter=$iface"
        done
    fi
    
    if [ -n "$ATTACH_INTERFACE" ]; then
        ARGS="$ARGS --attach-interface=$ATTACH_INTERFACE"
    fi
    
    log_info "启动参数: $ARGS"
    log_info "Metrics 端点: http://localhost:$METRICS_PORT/metrics"
    log_info "健康检查: http://localhost:$METRICS_PORT/health"
    
    # 启动 agent
    cd /workspace/netprobe
    exec ./bin/netprobe-agent $ARGS
}

# 清理函数
cleanup() {
    log_info "清理资源..."
    # 这里可以添加清理 TC 规则等操作
}

# 设置信号处理
trap cleanup EXIT

# 显示帮助
show_help() {
    cat << EOF
NetProbe Agent 启动脚本

使用方法:
  $0 [选项]

选项:
  -h, --help              显示此帮助信息
  -d, --debug             启用调试模式
  -p, --port PORT         Metrics 端口 (默认: 8081)
  -i, --interval INTERVAL 收集间隔 (默认: 5s)
  -f, --filter INTERFACES 接口过滤器，逗号分隔 (例如: eth0,wlan0)
  -a, --active-only       只导出活跃接口
  --attach INTERFACE      尝试附加 eBPF 程序到指定接口
  --build-only            仅构建，不启动
  --skip-build            跳过构建步骤

环境变量:
  METRICS_PORT           Metrics 端口
  COLLECT_INTERVAL       收集间隔
  INTERFACE_FILTER       接口过滤器
  ACTIVE_ONLY            只导出活跃接口 (true/false)
  DEBUG                  调试模式 (1/0)
  ATTACH_INTERFACE       附加接口

示例:
  # 基本启动
  sudo $0
  
  # 调试模式，监控特定接口
  sudo $0 --debug --filter eth0,wlan0 --active-only
  
  # 自定义端口和间隔
  sudo $0 --port 9090 --interval 3s
  
  # 尝试附加 eBPF 程序到 eth0
  sudo $0 --attach eth0
EOF
}

# 解析命令行参数
BUILD_ONLY=0
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -d|--debug)
            DEBUG=1
            shift
            ;;
        -p|--port)
            METRICS_PORT="$2"
            shift 2
            ;;
        -i|--interval)
            COLLECT_INTERVAL="$2"
            shift 2
            ;;
        -f|--filter)
            INTERFACE_FILTER="$2"
            shift 2
            ;;
        -a|--active-only)
            ACTIVE_ONLY=true
            shift
            ;;
        --attach)
            ATTACH_INTERFACE="$2"
            shift 2
            ;;
        --build-only)
            BUILD_ONLY=1
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        *)
            log_error "未知参数: $1"
            show_help
            exit 1
            ;;
    esac
done

# 主流程
main() {
    log_info "NetProbe Agent 启动脚本"
    
    check_dependencies
    
    if [ "$SKIP_BUILD" = "0" ]; then
        compile_ebpf
        build_agent
    fi
    
    if [ "$BUILD_ONLY" = "1" ]; then
        log_info "仅构建模式，退出"
        exit 0
    fi
    
    start_agent
}

# 运行主流程
main "$@"
