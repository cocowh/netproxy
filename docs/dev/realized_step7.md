# NetProxy 完工前最终审计与修复计划 (Step 7)

## 1. 现状综述 (Executive Summary)

经过对 NetProxy 项目代码库的全面审计（Code Audit），我们确认项目的基础架构（五层模型）、核心协议栈（SOCKS5, HTTP, SS）、以及关键技术组件（智能路由、内网穿透、链式代理）均已完成代码编写。

然而，在将这些组件组装成最终产品的过程中，存在 **5 个关键的集成缺陷 (Integration Defects)**。这些缺陷导致部分核心功能（如上游代理转发、内网穿透多租户路由）在实际运行时完全失效。

本文档详细列出了这些缺陷，并制定了最终的修复计划 (Final Fix Plan)，作为项目交付前的最后一份技术指导文档。

---

## 2. 严重缺陷分析 (Critical Defects)

此类缺陷导致功能不可用，必须优先修复。

### 2.1 缺陷一：路由模块“上游代理”配置缺失 (Missing Upstream Configuration)

*   **问题描述**: 
    智能路由 (`SmartDialer`) 和负载均衡器 (`LoadBalancer`) 依赖于一个可用代理列表 (`proxyList`) 来转发流量。然而，目前的配置系统 (`Config`) 和启动流程 (`main.go`) 中，**完全没有入口来定义这些上游代理**。
*   **代码证据**:
    *   `cmd/netproxy/main.go`: 初始化 Router 时，`proxyList` 参数被硬编码为 `nil`。
        ```go
        r := router.NewSimpleRouter(ruleEngine, nil, balancer, cfg.Routing.GeoIP)
        ```
    *   `internal/feature/router/router.go`: 当规则命中 `Proxy` 动作时，因 `r.proxyList` 为空直接返回错误：
        ```go
        if len(r.proxyList) == 0 { return RouteResult{}, errors.New("no proxy available") }
        ```
*   **影响**: 用户配置的所有 `proxy: ...` 规则都会失效，流量无法转发。

### 2.2 缺陷二：内网穿透 Bridge 路由逻辑不可用 (Broken Tunnel Routing)

*   **问题描述**: 
    `Tunnel Bridge` 目前的实现无法正确区分流量应该转发给哪个内网客户端。它采用了“演示级”的随机转发逻辑。
*   **代码证据**:
    *   `internal/protocol/tunnel/bridge.go`: `routeConnection` 方法随机遍历 `registry` 并取第一个 Session 进行转发。
        ```go
        b.registry.Range(func(key, value interface{}) bool { targetSession = value.(*ClientSession); return false })
        ```
*   **影响**: 
    *   在多客户端连接时，流量会被错误地路由到无关的客户端。
    *   缺少“端口 -> 客户端”或“域名 -> 客户端”的映射机制。
*   **资源泄露风险**: `Bridge` 启动的监听器未被跟踪，服务停止时无法关闭端口。

---

## 3. 功能缺失分析 (Missing Features)

此类缺陷表现为“代码已写好但未启用”，属于资源浪费。

### 3.1 缺失一：SPS (Smart Proxy Service) 协议栈未集成

*   **问题描述**: 
    `internal/protocol/sps` 模块已经实现了通过头部嗅探（Header Sniffing）同时支持 HTTP 和 SOCKS5 流量的能力，但在 `main.go` 中未被使用。
*   **代码证据**:
    *   `cmd/netproxy/main.go`: `getHandler` 工厂函数仅根据 `protocol` 字符串死板地选择 `socks5.NewSOCKS5Handler` 或 `http.NewHTTPHandler`。
*   **影响**: 用户无法配置单一端口（如 `:1080`）来同时服务 HTTP 和 SOCKS5 请求，这是现代代理工具的标配功能。

---

## 4. 架构与优化建议 (Architecture & Optimization)

此类缺陷影响系统的可维护性和高级功能体验。

### 4.1 DNS 模块孤立且不支持分流

*   **问题描述**: 
    DNS 模块 (`internal/feature/dns`) 目前是一个简单的转发器，只支持配置单一上游。它独立于核心路由系统。
*   **影响**: 
    *   **无法分流**: 无法实现“国内域名用国内 DNS，国外域名用国外 DoH”的策略。
    *   **性能/隐私折衷**: 用户被迫在“速度（国内 UDP DNS）”和“隐私/防污染（国外 DoH）”中二选一，无法兼得。

### 4.2 配置解析逻辑脆弱

*   **问题描述**: 
    `main.go` 中包含了大量手动解析逻辑（如手动解析 `proxy:` 规则字符串，手动 switch-case 初始化传输层），导致代码臃肿且难以测试。
*   **建议**: 应将解析逻辑下沉到 `config` 包或各模块的工厂方法中。

---

## 5. 最终修复计划 (Final Fix Plan)

为了完成项目交付，必须按顺序执行以下修复：

### Step 7.1: 修复上游代理配置 (Fix Upstream Config)
1.  **修改 `internal/core/config/config.go`**:
    *   在 `RoutingConfig` 中增加 `Upstreams []string` 字段。
2.  **修改 `cmd/netproxy/main.go`**:
    *   在读取 Config 后，将 `cfg.Routing.Upstreams` 传递给 `router.NewSimpleRouter`。

### Step 7.2: 重构 Tunnel Bridge 路由 (Fix Bridge Routing)
1.  **修改 `internal/core/config/config.go`**:
    *   修改 `TunnelConfig`，增加 `Tunnels map[string]string` (e.g., `":8081": "client-id-1"`).
    *   废弃单一的 `DataAddr`。
2.  **修改 `internal/protocol/tunnel/bridge.go`**:
    *   `NewBridge` 接受端口映射配置。
    *   为每个映射端口启动一个监听器。
    *   收到流量时，根据监听端口查找目标 `ClientID`，然后定向获取 Session。

### Step 7.3: 集成 SPS 协议 (Integrate SPS)
1.  **修改 `cmd/netproxy/main.go`**:
    *   在 `getHandler` 中增加 `case "mixed":` 或 `case "sps":`。
    *   调用 `sps.NewSPSHandler`，传入 SOCKS5 和 HTTP Handler 实例。

### Step 7.4: (Optional) 优化 DNS
*   如果时间允许，修改 `DNSConfig` 支持 `RemoteUpstream` 和 `LocalUpstream`，并根据 `RuleEngine` 进行简单的域名分流。

---

**执行建议**: 请直接按照 Step 7.1 -> 7.2 -> 7.3 的顺序进行代码修正。
