# NetProxy 代理功能完整性分析与后续实现计划 (Step 3)

## 1. 现状分析 (Gap Analysis)

基于 `docs` 目录下的设计文档以及 `internal` 目录下的代码实现情况，对当前 NetProxy 项目的代理功能完整性进行分析。

### 1.1 已实现部分 (Implemented)

*   **基础架构**: 服务实例 (`Instance`)、监听器管理 (`ListenerManager`)、配置结构已就绪。
*   **多协议支持**:
    *   `SOCKS5`: 基于 `armon/go-socks5` 的基础实现。
    *   `HTTP`: 基于 `elazarl/goproxy` 的基础实现。
    *   `Shadowsocks (SS)`: 实现了 Handler 和 Dialer (Client)。
    *   `SPS`: 实现了基于头部嗅探的协议分发。
*   **传输层**: 支持 TCP, KCP, WebSocket, SSH, TLS 等多种传输方式，并实现了 `ProxyDialer` 接口。
*   **链式代理 (核心逻辑)**: `Chain` 也就是 `ProxyDialer` 的嵌套构建逻辑已在 `internal/service/instance/chain.go` 中实现。
*   **内网穿透 (核心逻辑)**: `Tunnel` 的 `Bridge` 和 `Client` 逻辑在 `internal/protocol/tunnel` 中已实现。
*   **功能模块**: 简单的路由 (SimpleRouter)、简单的负载均衡 (RoundRobin/Random)、HTTP API 认证。

### 1.2 缺失与断层 (Missing & Disconnected)

尽管核心逻辑代码已存在，但各组件之间存在**集成断层**，导致功能无法真正跑通。主要问题如下：

1.  **链式代理未生效 (Critical)**:
    *   虽然 `handleWithChain` 构建了 `Dialer` 链并注入了 `Context`，但 **Protocol Handlers (SOCKS5, HTTP, SS) 并未从 Context 中提取并使用这个 Dialer**。
    *   目前 `SOCKS5` Handler 使用默认的 `net.Dial`。
    *   目前 `HTTP` Handler 使用默认的 `http.Transport` 或 `net.Dial`。
    *   目前 `SS` Handler 直接调用 `net.Dial`。
    *   **结论**: 配置了链式代理也不会生效，流量只会直连。

2.  **内网穿透模块未集成**:
    *   `internal/protocol/tunnel` 下的代码是独立的，`ListenerManager` 和 `Config` 中没有针对 Tunnel (Bridge/Client) 的启动逻辑。
    *   无法通过配置文件启动穿透服务。

3.  **高级路由功能缺失**:
    *   目前的 `SimpleRouter` 仅支持简单的黑白名单。
    *   缺少 **GeoIP** (基于 IP 的国家/地区路由)。
    *   缺少 **Domain List** (geosite/gfwlist) 支持。

4.  **配置解析不完整**:
    *   `ListenerManager` 中大量传输层参数（如 TLS 证书路径、KCP 参数、SSH 密钥等）目前硬编码或未解析 (`TODO` 状态)。

5.  **DNS 功能简陋**:
    *   仅实现了简单的 UDP Forwarding，不支持 DoH/DoT，无缓存 (Cache)，无 Hosts 文件支持。

---

## 2. 实现计划 (Implementation Plan - Step 3)

为了完善代理功能，需执行以下实现步骤。

### 2.1 任务 1: 修复链式代理集成 (Fix Chain Proxy Integration)

**目标**: 让所有协议 Handler 使用 Context 中注入的 `ProxyDialer` 进行出站连接。

**实现思路**:
1.  **定义 Context Key**: 在 `internal/core/context` 或 `transport` 包中定义标准 Key，例如 `CtxKeyDialer`。
2.  **改造 `SOCKS5` Handler**:
    *   实现 `proxy.Dialer` 接口 (from `armon/go-socks5`)，在 `Dial` 方法中从 Context 获取 `ProxyDialer` 并调用。
    *   在 `NewSOCKS5Handler` 时将此 Custom Dialer 注入配置。
3.  **改造 `HTTP` Handler**:
    *   自定义 `goproxy.ProxyHttpServer` 的 `Tr` (Transport) 和 `ConnectDial`。
    *   实现一个 `http.RoundTripper`，其底层使用 Context 中的 `ProxyDialer` 建立连接。
4.  **改造 `SS` Handler**:
    *   修改 `internal/protocol/ss/handler.go`，将 `net.Dial` 替换为从 Context 获取 Dialer。

### 2.2 任务 2: 集成内网穿透服务 (Integrate Tunnel Service)

**目标**: 支持通过配置文件启动 Bridge 和 Client。

**实现思路**:
1.  **扩展配置结构**: 在 `Config` 中增加 `Tunnel` 部分。
    ```go
    type TunnelConfig struct {
        Mode string // "bridge" or "client"
        ControlAddr string
        DataAddr string // For Bridge
        ServerAddr string // For Client
        TargetAddr string // For Client (Local service)
        Key string
    }
    ```
2.  **服务启动逻辑**:
    *   在 `internal/app` 或 `LifecycleManager` 中，根据配置启动 `Tunnel.Bridge` 或 `Tunnel.Client` 实例。
    *   确保 Tunnel 服务与主 Proxy 服务并发运行。

### 2.3 任务 3: 实现高级路由 (Advanced Router)

**目标**: 支持 GeoIP 和 域名列表路由。

**实现思路**:
1.  **引入依赖**:
    *   GeoIP: `github.com/oschwald/geoip2-golang` (需下载 MMDB)。
    *   Domain: 解析 `v2ray-rules-dat` 或类似的文本列表。
2.  **增强 `Router`**:
    *   实现 `GeoIPMatcher`。
    *   实现 `DomainMatcher` (基数树/Trie 树优化匹配)。
3.  **规则配置**: 支持类似于 "block: geoip:cn", "proxy: domain:google.com" 的规则描述。

### 2.4 任务 4: 完善监听器配置解析 (Complete Listener Parsing)

**目标**: 支持 TLS, KCP, SSH 的详细参数配置。

**实现思路**:
1.  **修改 `ListenerConfig`**: 确保 `Options map[string]interface{}` 能正确映射到具体配置结构。
2.  **实现 Factory 方法**:
    *   `parseTLSConfig`: 读取 Cert/Key 文件。
    *   `parseKCPConfig`: 读取 DataShards, ParityShards, CryptKey 等。
    *   `parseSSHConfig`: 读取 User, Key, AuthorizedKeys 等。

### 2.5 任务 5: 增强 DNS 模块 (Enhance DNS)

**目标**: 实现 DNS 缓存和 DoH 支持。

**实现思路**:
1.  **Cache**: 使用 `github.com/patrickmn/go-cache` 在 `ServeDNS` 中缓存响应。
2.  **Upstream**: 抽象 `UpstreamResolver` 接口。
    *   `UDPResolver`: 现有的。
    *   `DoHResolver`: 使用 HTTP Client 请求 DoH 服务 (如 `https://1.1.1.1/dns-query`)。

## 3. 建议执行顺序

1.  **Task 1 (Chain Integration)**: 最核心功能，必须优先解决。
2.  **Task 4 (Listener Options)**: 基础功能的完善，便于测试多种协议。
3.  **Task 2 (Tunnel)**: 独立模块集成。
4.  **Task 3 (Router)**: 增强功能。
5.  **Task 5 (DNS)**: 增强功能。
