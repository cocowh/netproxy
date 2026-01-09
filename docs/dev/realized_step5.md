# NetProxy 完工情况分析与最终交付计划 (Step 5)

## 1. 现状分析 (Status Analysis)

基于 `docs` 目录下的设计文档、架构文档以及当前的代码实现 (`internal/`, `cmd/`)，对 NetProxy 项目进行全面的差异分析 (Gap Analysis)。

### 1.1 已达成目标 (Achieved Goals)

项目已成功实现了核心架构设计的 80% 以上，解决了 Step 4 中提出的关键架构缺陷。

*   **智能路由 (Smart Routing) 已落地**:
    *   `SmartDialer` (internal/transport/smart_dialer.go) 成功实现了 "延迟决策" 模式。
    *   路由决策不再发生在握手前，而是推迟到协议解析出目标地址 (Dial) 时。
    *   支持了基于 `ClientIP` (GeoIP) 和 `TargetHost` (Domain) 的组合策略。
*   **配置系统增强**:
    *   `Config` 结构体支持了 `Routing` 和 `Tunnel` 配置。
    *   `main.go` 中实现了规则的解析和加载 logic。
*   **功能模块集成**:
    *   **Tunnel**: 内网穿透的 Bridge 和 Client 模式已集成到启动流程。
    *   **Stats**: 实现了连接级和流量级的统计收集 (`StatsCollector`)，并提供了 Admin API。
    *   **Protocols**: SOCKS5, HTTP, SS 协议均已实现并适配了新的 `SmartDialer`。

### 1.2 尚未满足的需求 (Unmet Requirements)

尽管核心逻辑已跑通，但要达到 "成品级" (Production Ready) 并在功能上完全覆盖 `architecture.md` 的描述，仍存在以下明显缺口：

#### 1.2.1 配置系统的灵活性缺失 (Configuration Flexibility Gap)
*   **问题**: 目前的 `Config` 结构体中，`Server` 只有一个简单的 `ListenAddr`。无法通过配置文件定义 "在端口 1080 开启 SOCKS5，同时在端口 8080 开启 HTTP"。
*   **现状**: `cmd/netproxy/main.go` 中**硬编码**了 SOCKS5 (:1080) 和 HTTP (:8080) 的启动逻辑。
*   **需求**: 需要支持多监听器配置数组，例如：
    ```yaml
    listeners:
      - protocol: socks5
        addr: :1080
      - protocol: http
        addr: :8080
        auth: true
    ```

#### 1.2.2 负载均衡模块未装配 (LoadBalancer Detached)
*   **问题**: `internal/feature/loadbalancer` 模块虽然存在，但未被 `Router` 使用。
*   **现状**: `SimpleRouter` 在处理 `Proxy` 动作时，直接硬编码取了第一个代理节点 (`r.proxyList[0]`)。
*   **需求**: `Router` 需要持有 `LoadBalancer` 实例，根据策略 (RoundRobin/Random) 选择下一跳。

#### 1.2.3 传输层完整性 (Transport Completeness)
*   **问题**: 架构文档中提到的 `Websocket`, `TLS`, `SSH` 传输层封装在 `config` 中缺乏统一的配置入口。
*   **现状**: 代码中有相关文件，但 `ListenerManager` 和 `SmartDialer` 的构建逻辑中尚未完全打通这些高级传输方式的参数传递。

---

## 2. 最终交付计划 (Final Delivery Plan)

为了完全满足初始目标需求，需要执行最后一步的冲刺。

### 2.1 任务 1: 重构监听器配置 (Refactor Listener Config)

**目标**: 移除 `main.go` 中的硬编码，实现完全由配置文件驱动的服务启动。

**实现步骤**:
1.  修改 `internal/core/config/config.go`:
    *   废弃 `ServerConfig`。
    *   新增 `Listeners []ListenerConfig`。
2.  修改 `cmd/netproxy/main.go`:
    *   遍历 `cfg.Listeners`。
    *   使用工厂模式动态创建 `Instance` 和 `Listener`。
    *   统一管理所有 Listener 的生命周期。

### 2.2 任务 2: 装配负载均衡 (Integrate LoadBalancer)

**目标**: 让路由支持多节点负载均衡。

**实现步骤**:
1.  修改 `SimpleRouter`，将 `proxyList []string` 替换为 `balancer loadbalancer.Balancer` 和 `peers []string`。
2.  在 `Route` 方法中，当 Action 为 Proxy 时，调用 `r.balancer.Next(ctx, r.peers)` 获取目标。
3.  在 `main.go` 中初始化 `Router` 时注入 `RoundRobin` 或 `Random` Balancer。

### 2.3 任务 3: 完善 Admin/Stats (Polishing)

**目标**: 确保 Admin API 返回的数据准确反映当前系统状态。

**实现步骤**:
1.  确保所有 `Instance` 创建的连接都正确注册到了 `StatsCollector`。
2.  验证 `/stats` 和 `/conns` 接口输出。

---

## 3. 结论

项目目前处于 **90% 完成度**。核心架构稳健，关键难点（链式代理、智能路由、内网穿透）均已攻克。剩余工作主要集中在 **配置驱动化** 和 **模块组装** 上。完成上述计划后，项目将完全满足 `docs/dev/design.md` 和 `architecture.md` 中的设计目标。
