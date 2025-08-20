# 安装指南

## 前置要求

### 系统要求

- Linux 内核版本 4.18 或更高（支持 eBPF）
- Kubernetes 集群版本 1.20 或更高
- 节点需要有 CAP_SYS_ADMIN 和 CAP_NET_ADMIN 权限

### 工具要求

- `kubectl` 命令行工具
- `helm`（可选，用于 Helm 安装）

## 检查系统兼容性

在安装之前，请检查系统是否支持 eBPF：

```bash
# 检查内核版本
uname -r

# 检查 eBPF 支持
ls /sys/fs/bpf/

# 检查必要的内核配置
zcat /proc/config.gz | grep -E "(CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_BPF_JIT)"
```

## 安装方法

### 方法一：使用 kubectl 直接安装

1. 克隆项目：
```bash
git clone https://github.com/your-org/kube-net-probe.git
cd kube-net-probe
```

2. 构建 eBPF 程序：
```bash
make build-ebpf
```

3. 构建 Docker 镜像：
```bash
make docker-build
```

4. 部署到集群：
```bash
kubectl apply -f deploy/
```

### 方法二：使用 CLI 工具安装

1. 下载并安装 CLI 工具：
```bash
# 下载最新版本
wget https://github.com/your-org/kube-net-probe/releases/latest/download/knp-linux-amd64
chmod +x knp-linux-amd64
sudo mv knp-linux-amd64 /usr/local/bin/knp

# 或者从源码构建
make build
sudo cp bin/cli /usr/local/bin/knp
```

2. 使用 CLI 安装：
```bash
knp install
```

### 方法三：使用 Helm 安装（推荐）

```bash
# 添加 Helm 仓库
helm repo add kube-net-probe https://your-org.github.io/kube-net-probe
helm repo update

# 安装
helm install kube-net-probe kube-net-probe/kube-net-probe
```

## 验证安装

### 检查组件状态

```bash
# 检查 namespace
kubectl get ns kube-net-probe

# 检查 manager
kubectl get deployment kube-net-probe-manager -n kube-net-probe

# 检查 agent
kubectl get daemonset kube-net-probe-agent -n kube-net-probe

# 检查所有 pods
kubectl get pods -n kube-net-probe
```

### 检查系统状态

```bash
# 使用 CLI 检查状态
knp status

# 检查网络监控
knp get network

# 检查安全监控
knp get security
```

### 检查 API 服务

```bash
# 端口转发到 API 服务
kubectl port-forward -n kube-net-probe svc/kube-net-probe-manager 9090:9090

# 测试 API
curl http://localhost:9090/health
curl http://localhost:9090/api/v1/network/metrics
```

## 配置

### 基础配置

KubeNetProbe 的配置主要通过以下几种方式：

1. **环境变量**：通过 Deployment 和 DaemonSet 中的环境变量
2. **ConfigMap**：存储 eBPF 程序和配置文件
3. **CLI 参数**：启动时的命令行参数

### 自定义配置

创建自定义配置文件：

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kube-net-probe-config
  namespace: kube-net-probe
data:
  config.yaml: |
    manager:
      api:
        bind_address: ":9090"
        enable_cors: true
      metrics:
        bind_address: ":8080"
        enable_profiling: false
    
    agent:
      collection:
        interval: "5s"
        buffer_size: 1024
      ebpf:
        programs:
          - network
          - security
          - performance
    
    monitoring:
      network:
        track_flows: true
        track_connections: true
      security:
        detect_port_scans: true
        detect_anomalies: true
      performance:
        collect_latency: true
        collect_throughput: true
```

### eBPF 程序配置

配置要加载的 eBPF 程序：

```bash
# 编辑 agent DaemonSet
kubectl edit daemonset kube-net-probe-agent -n kube-net-probe

# 修改 args 部分
args:
- --ebpf-programs=network,security,performance
- --manager-address=kube-net-probe-manager.kube-net-probe.svc.cluster.local:9090
```

## 故障排除

### 常见问题

1. **eBPF 程序加载失败**
```bash
# 检查内核支持
ls /sys/fs/bpf/

# 检查权限
kubectl describe pod <agent-pod> -n kube-net-probe
```

2. **Agent 无法连接到 Manager**
```bash
# 检查网络连接
kubectl exec -it <agent-pod> -n kube-net-probe -- nslookup kube-net-probe-manager.kube-net-probe.svc.cluster.local

# 检查服务端口
kubectl get svc kube-net-probe-manager -n kube-net-probe
```

3. **权限问题**
```bash
# 检查 ServiceAccount
kubectl get serviceaccount -n kube-net-probe

# 检查 RBAC
kubectl get clusterrole kube-net-probe-manager
kubectl get clusterrolebinding kube-net-probe-manager
```

### 日志查看

```bash
# Manager 日志
kubectl logs -l app=kube-net-probe-manager -n kube-net-probe -f

# Agent 日志
kubectl logs -l app=kube-net-probe-agent -n kube-net-probe -f

# 使用 CLI 查看日志
knp logs manager
knp logs agent
```

### 调试模式

启用详细日志：

```bash
# 编辑 deployment
kubectl edit deployment kube-net-probe-manager -n kube-net-probe

# 添加 verbose 参数
args:
- --v=4
- --logtostderr=true
```

## 卸载

### 使用 kubectl 卸载

```bash
kubectl delete -f deploy/
```

### 使用 CLI 卸载

```bash
knp uninstall
```

### 使用 Helm 卸载

```bash
helm uninstall kube-net-probe
```

### 清理资源

```bash
# 删除 CRDs（如果有）
kubectl delete crd -l app=kube-net-probe

# 删除 namespace
kubectl delete namespace kube-net-probe
```

## 升级

### 升级到新版本

```bash
# 构建新镜像
make docker-build VERSION=v0.2.0

# 更新部署
kubectl set image deployment/kube-net-probe-manager manager=kube-net-probe-manager:v0.2.0 -n kube-net-probe
kubectl set image daemonset/kube-net-probe-agent agent=kube-net-probe-agent:v0.2.0 -n kube-net-probe
```

### 滚动升级

```bash
# 检查升级状态
kubectl rollout status deployment/kube-net-probe-manager -n kube-net-probe
kubectl rollout status daemonset/kube-net-probe-agent -n kube-net-probe

# 回滚（如果需要）
kubectl rollout undo deployment/kube-net-probe-manager -n kube-net-probe
```
