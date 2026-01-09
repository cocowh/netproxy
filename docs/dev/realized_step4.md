# NetProxy 实现现状分析与修正计划 (Step 4)

## 1. 现状分析 (Status Analysis)

经过对当前代码库 (`internal/`, `cmd/`) 的深入审查，并对比 `docs` 目录下的设计文档，我们发现项目的实际代码进度已优于 `realized_step3.md` 的描述，但在**核心路由逻辑**上存在重大架构缺陷，导致高级功能无法闭环。

### 1.1 已超前完成的功能 (Completed ahead of plan)

以下功能在 `step3` 中被标记为缺失，但代码中实际上已经实现或集成了核心逻辑：

*   **链式代理集成 (Chain Integration)**: `Protocol Handlers` (SOCKS5, HTTP, SS) 均已修改为从 `Context` 中提取 `Dialer`，具备了使用代理链的能力。
*   **内网穿透集成 (Tunnel Integration)**: `main.go` 中已包含启动 `Bridge` 和 `Client` 的逻辑，且 `Config` 中已定义相关字段。
*   **监听器配置解析 (Listener Parsing)**: 支持解析 KCP, SSH, TLS 的复杂参数。
*   **DNS 增强**: 已实现 DoH 支持和基础缓存。
*   **高级路由匹配器**: `GeoIPMatcher` 和 `DomainMatcher` 代码已存在。

### 1.2 核心逻辑缺陷 (Critical Architectural Defect)

尽管组件都已就位，但**路由决策的时机 (Routing Timing)** 存在根本性错误，导致“基于域名的路由（如 GFWList）”和“基于目标 IP 的路由”**完全不可用**。

*   **问题描述**:
    *   目前的逻辑是：`ServiceInstance` 接收连接 -> **握手前 (Pre-handshake)** 调用 `Router.Route` -> 生成 `Dialer` -> 执行协议握手 (Handshake)。
    *   **后果**: 在握手前，代理服务器**根本不知道**客户端想要访问的目标地址 (Target Address)。此时 `Router` 只能看到客户端的源 IP (Client IP)。
    *   **影响**: 用户配置 "google.com 走代理，baidu.com 直连" 将无法生效，因为路由发生时还不知道目标是 google 还是 baidu。

### 1.3 其他未满足需求 (Unmet Requirements)

1.  **配置系统缺失规则加载**:
    *   虽然代码里有 `AddRule`，但 `Config` 结构体中没有定义加载规则文件（如 `geosite.dat`, `geoip.dat` 或自定义规则列表）的字段。
    *   用户无法通过配置文件控制路由策略。
2.  **Admin API 不完整**:
    *   `/stats` 接口返回的是 Mock 数据。
    *   `/conns` 接口未实现。
3.  **LoadBalancer 未集成**:
    *   虽然有目录结构，但 `Router` 中选择下一跳时直接取了第一个 (`r.proxyList[0]`)，未应用负载均衡算法。

---

## 2. 修正方案 (Correction Plan)

为了满足最初的目标需求，必须重构路由逻辑。

### 2.1 重构路由决策流 (Refactor Routing Flow)

**目标**: 将路由决策推迟到 `Dial` 阶段（即握手后，连接目标前）。

**方案**:
1.  **引入 `SmartDialer`**:
    *   不再在 `Instance` 层预先构建固定的 `ChainDialer`。
    *   而是向 `Context` 中注入一个智能的 `SmartDialer`。
    *   `SmartDialer` 包含 `Router` 的引用。
2.  **实现 `SmartDialer.Dial(network, addr)`**:
    *   当 Protocol Handler (SOCKS5/HTTP) 解析出目标地址并调用 `Dial` 时：
    *   `SmartDialer` 拿着 `addr` (Target) 和 `Context` (包含 Client IP) 去询问 `Router`。
    *   `Router` 匹配规则，返回 `NextHops` (代理链)。
    *   `SmartDialer` 动态构建代理链并建立连接。

### 2.2 完善配置结构 (Enhance Configuration)

**目标**: 允许用户配置路由规则。

**方案**:
在 `Config` 中增加 `Routing` 字段：
```yaml
routing:
  geoip: "./GeoLite2-Country.mmdb"
  rules:
    - "proxy: domain:google.com"
    - "block: geoip:cn"
    - "direct: domain:baidu.com"
```

### 2.3 完善 Admin API 与 Stats

**目标**: 实现真实的监控。

**方案**:
*   `StatsCollector` 需要注册到全局，并在 `SmartDialer` 和 `Instance` 中进行原子计数。
*   实现 `ConnectionRegistry` 追踪活跃连接，用于 `/conns` 接口。

---

## 3. 下一步执行任务 (Next Steps)

1.  **Refactor SmartDialer**: 实现延迟路由决策逻辑。
2.  **Config Rules**: 实现规则配置的解析与加载。
3.  **Real Stats**: 对接真实的统计数据。
