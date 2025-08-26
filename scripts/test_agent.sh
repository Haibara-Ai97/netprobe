#!/bin/bash

# NetProbe Agent 测试脚本

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 测试配置
AGENT_PORT=${AGENT_PORT:-8081}
METRICS_ENDPOINT="http://localhost:$AGENT_PORT/metrics"
HEALTH_ENDPOINT="http://localhost:$AGENT_PORT/health"
TEST_TIMEOUT=${TEST_TIMEOUT:-30}

# 等待服务启动
wait_for_service() {
    local endpoint=$1
    local timeout=$2
    local count=0
    
    log_info "等待服务启动: $endpoint"
    
    while [ $count -lt $timeout ]; do
        if curl -s -f "$endpoint" > /dev/null 2>&1; then
            log_info "服务已启动"
            return 0
        fi
        
        sleep 1
        count=$((count + 1))
        
        if [ $((count % 5)) -eq 0 ]; then
            log_info "等待中... ($count/$timeout)"
        fi
    done
    
    log_error "服务启动超时"
    return 1
}

# 测试 metrics 端点
test_metrics_endpoint() {
    log_info "测试 Metrics 端点..."
    
    # 检查响应状态
    local status=$(curl -s -o /dev/null -w "%{http_code}" "$METRICS_ENDPOINT")
    if [ "$status" != "200" ]; then
        log_error "Metrics 端点返回状态码: $status"
        return 1
    fi
    
    # 获取 metrics 内容
    local metrics=$(curl -s "$METRICS_ENDPOINT")
    local metrics_count=$(echo "$metrics" | grep -c "^netprobe_" || true)
    
    log_info "Metrics 状态码: $status"
    log_info "发现 $metrics_count 个 netprobe 指标"
    
    # 检查必要的指标
    local required_metrics=(
        "netprobe_up"
        "netprobe_collection_total"
        "netprobe_last_collection_timestamp_seconds"
    )
    
    for metric in "${required_metrics[@]}"; do
        if echo "$metrics" | grep -q "$metric"; then
            log_info "✅ 找到指标: $metric"
        else
            log_warn "⚠️  缺少指标: $metric"
        fi
    done
    
    # 检查 TC 指标（如果有数据的话）
    local tc_metrics=$(echo "$metrics" | grep -c "netprobe_tc_" || true)
    if [ $tc_metrics -gt 0 ]; then
        log_info "✅ 找到 $tc_metrics 个 TC 相关指标"
        
        # 显示一些示例 TC 指标
        echo "$metrics" | grep "netprobe_tc_" | head -5 | while read line; do
            log_info "  示例: $line"
        done
    else
        log_warn "⚠️  暂无 TC 相关指标数据"
    fi
    
    return 0
}

# 测试健康检查端点
test_health_endpoint() {
    log_info "测试健康检查端点..."
    
    local status=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT")
    if [ "$status" != "200" ]; then
        log_error "健康检查端点返回状态码: $status"
        return 1
    fi
    
    local health=$(curl -s "$HEALTH_ENDPOINT")
    log_info "健康检查响应:"
    echo "$health" | jq . 2>/dev/null || echo "$health"
    
    # 检查健康状态
    local health_status=$(echo "$health" | jq -r '.status' 2>/dev/null || echo "unknown")
    if [ "$health_status" = "ok" ]; then
        log_info "✅ 服务健康状态正常"
    else
        log_warn "⚠️  服务健康状态: $health_status"
    fi
    
    return 0
}

# 测试指标更新
test_metrics_updates() {
    log_info "测试指标更新..."
    
    # 获取初始收集计数
    local initial_collections=$(curl -s "$METRICS_ENDPOINT" | grep "netprobe_collection_total" | awk '{print $2}' | head -1)
    log_info "初始收集计数: $initial_collections"
    
    # 等待一段时间
    log_info "等待 10 秒以观察指标更新..."
    sleep 10
    
    # 获取更新后的收集计数
    local updated_collections=$(curl -s "$METRICS_ENDPOINT" | grep "netprobe_collection_total" | awk '{print $2}' | head -1)
    log_info "更新后收集计数: $updated_collections"
    
    # 比较收集计数
    if [ "$updated_collections" != "$initial_collections" ]; then
        log_info "✅ 指标正在更新"
        local diff=$((updated_collections - initial_collections))
        log_info "收集计数增加了: $diff"
    else
        log_warn "⚠️  指标似乎没有更新"
    fi
    
    return 0
}

# 生成网络流量（用于测试）
generate_traffic() {
    log_info "生成测试网络流量..."
    
    # ping 本地回环接口
    ping -c 5 127.0.0.1 > /dev/null 2>&1 &
    
    # 如果有 curl，尝试访问一些网站
    if command -v curl > /dev/null; then
        curl -s --max-time 5 http://httpbin.org/ip > /dev/null 2>&1 &
        curl -s --max-time 5 http://httpbin.org/headers > /dev/null 2>&1 &
    fi
    
    # 等待流量生成完成
    sleep 6
    log_info "测试流量生成完成"
}

# 显示网络接口信息
show_network_info() {
    log_info "显示网络接口信息..."
    
    echo "活跃网络接口:"
    ip link show | grep "state UP" | while read line; do
        iface=$(echo "$line" | awk -F: '{print $2}' | tr -d ' ')
        log_info "  - $iface"
    done
    
    echo ""
    echo "网络统计 (接收/发送包数):"
    cat /proc/net/dev | tail -n +3 | while read line; do
        iface=$(echo "$line" | awk -F: '{print $1}' | tr -d ' ')
        rx_packets=$(echo "$line" | awk '{print $2}')
        tx_packets=$(echo "$line" | awk '{print $10}')
        
        if [ "$rx_packets" -gt 0 ] || [ "$tx_packets" -gt 0 ]; then
            log_info "  $iface: RX=$rx_packets, TX=$tx_packets"
        fi
    done
}

# 完整的功能测试
run_functional_test() {
    log_info "运行功能测试..."
    
    # 等待服务启动
    if ! wait_for_service "$HEALTH_ENDPOINT" $TEST_TIMEOUT; then
        return 1
    fi
    
    # 显示网络信息
    show_network_info
    
    # 测试健康检查
    if ! test_health_endpoint; then
        return 1
    fi
    
    # 测试 metrics 端点
    if ! test_metrics_endpoint; then
        return 1
    fi
    
    # 生成一些网络流量
    generate_traffic
    
    # 测试指标更新
    if ! test_metrics_updates; then
        return 1
    fi
    
    log_info "✅ 所有功能测试通过"
    return 0
}

# 性能测试
run_performance_test() {
    log_info "运行性能测试..."
    
    # 压力测试 metrics 端点
    log_info "压力测试 metrics 端点 (100 个并发请求)..."
    
    local start_time=$(date +%s)
    
    # 使用 xargs 并行发送请求
    seq 1 100 | xargs -n1 -P10 -I{} curl -s -o /dev/null "$METRICS_ENDPOINT"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log_info "压力测试完成，耗时: ${duration}s"
    
    # 检查服务是否仍然响应
    if curl -s -f "$HEALTH_ENDPOINT" > /dev/null; then
        log_info "✅ 服务在压力测试后仍然响应正常"
    else
        log_error "❌ 服务在压力测试后无响应"
        return 1
    fi
    
    return 0
}

# 显示帮助
show_help() {
    cat << EOF
NetProbe Agent 测试脚本

使用方法:
  $0 [选项]

选项:
  -h, --help              显示此帮助信息
  -p, --port PORT         Agent 端口 (默认: 8081)
  -t, --timeout SECONDS   测试超时时间 (默认: 30)
  -f, --functional        只运行功能测试
  -P, --performance       只运行性能测试
  -m, --metrics-only      只测试 metrics 端点
  -H, --health-only       只测试健康检查端点

环境变量:
  AGENT_PORT             Agent 端口
  TEST_TIMEOUT           测试超时时间

示例:
  # 运行所有测试
  $0
  
  # 指定端口
  $0 --port 9090
  
  # 只运行功能测试
  $0 --functional
  
  # 只测试 metrics 端点
  $0 --metrics-only
EOF
}

# 解析命令行参数
RUN_FUNCTIONAL=1
RUN_PERFORMANCE=1
METRICS_ONLY=0
HEALTH_ONLY=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -p|--port)
            AGENT_PORT="$2"
            METRICS_ENDPOINT="http://localhost:$AGENT_PORT/metrics"
            HEALTH_ENDPOINT="http://localhost:$AGENT_PORT/health"
            shift 2
            ;;
        -t|--timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        -f|--functional)
            RUN_PERFORMANCE=0
            shift
            ;;
        -P|--performance)
            RUN_FUNCTIONAL=0
            shift
            ;;
        -m|--metrics-only)
            METRICS_ONLY=1
            RUN_PERFORMANCE=0
            shift
            ;;
        -H|--health-only)
            HEALTH_ONLY=1
            RUN_PERFORMANCE=0
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
    log_info "NetProbe Agent 测试脚本"
    log_info "测试端点: $METRICS_ENDPOINT"
    log_info "健康检查: $HEALTH_ENDPOINT"
    
    # 检查必要工具
    if ! command -v curl > /dev/null; then
        log_error "需要 curl 工具"
        exit 1
    fi
    
    local exit_code=0
    
    if [ "$HEALTH_ONLY" = "1" ]; then
        if ! wait_for_service "$HEALTH_ENDPOINT" $TEST_TIMEOUT || ! test_health_endpoint; then
            exit_code=1
        fi
    elif [ "$METRICS_ONLY" = "1" ]; then
        if ! wait_for_service "$METRICS_ENDPOINT" $TEST_TIMEOUT || ! test_metrics_endpoint; then
            exit_code=1
        fi
    else
        if [ "$RUN_FUNCTIONAL" = "1" ]; then
            if ! run_functional_test; then
                exit_code=1
            fi
        fi
        
        if [ "$RUN_PERFORMANCE" = "1" ] && [ $exit_code -eq 0 ]; then
            if ! run_performance_test; then
                exit_code=1
            fi
        fi
    fi
    
    if [ $exit_code -eq 0 ]; then
        log_info "🎉 所有测试完成"
    else
        log_error "💥 测试失败"
    fi
    
    exit $exit_code
}

# 运行主流程
main "$@"
