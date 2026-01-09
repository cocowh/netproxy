# NetProxy 生产级验收与缺陷修复计划 (Step 10)

## 1. 现状综述 (Executive Summary)

经过 Step 9 的专项修复，NetProxy 的核心网络层（Shadowsocks UDP）、路由层（GeoIP 性能、Split-DNS）已达到较高水准。对照 `docs/dev/architecture.md` 和 `design.md` 的初始目标，项目已完成约 95% 的功能。

然而，在最后的生产级验收（Production Acceptance）审查中，我们发现了 **4 个影响长期运维和安全性的缺陷**。虽然这些不影响“跑通演示”，但对于一个宣称“生产级”的项目来说，是不可接受的。

---

## 2. 缺陷与不足分析 (Gap Analysis)

### 2.1 严重缺陷：SPS (Smart Proxy Service) 协议缺乏 UDP 支持 (Critical)
*   **问题描述**: `internal/protocol/sps` 模块目前仅实现了 TCP 协议的头部嗅探（Sniffing）。当用户配置 SPS 端口时（即一个端口同时支持 HTTP/SOCKS5），**UDP 流量会被完全丢弃**。
*   **影响**: 用户无法通过 SPS 端口使用 SOCKS5 UDP Associate 功能。DNS 查询和 QUIC 流量在 SPS 模式下失效。
*   **预期**: SPS 应当具备处理 UDP 数据包的能力，或者至少能透传 SOCKS5 的 UDP 请求。

### 2.2 安全缺陷：API 与 Admin 接口无鉴权 (High)
*   **问题描述**: 
    *   管理接口 `:9090` (`internal/core/admin/server.go`) 完全裸奔，没有任何认证机制。任何人只要能访问该端口，就能查看连接信息、Kill 连接甚至重载配置。
    *   Admin Server 绑定地址硬编码为 `:9090`，且只在 `main.go` 中初始化，缺乏灵活性。
*   **影响**: 极大的安全隐患，尤其是在公网部署时。

### 2.3 功能缺陷：链式代理缺少 "Transport Layer" 支持 (Medium)
*   **问题描述**: Step 8 曾提到过此问题，但在 Step 9 中主要解决了 UDP 和路由。目前 `SmartDialer` 构建代理链时，底层的 `dialer` 只能是 TCP。无法实现 **SOCKS5 over TLS** 或 **VMess over WebSocket** 这种高级传输组合。
*   **影响**: 在高阻断环境下（需要 TLS/WS 伪装），当前的链式代理生存能力较弱。

### 2.4 工程缺陷：单元测试覆盖率极低 (Low)
*   **问题描述**: 核心模块（Router, SmartDialer, SPS）几乎没有配套的 `_test.go` 文件。
*   **影响**: 代码重构和维护风险高，缺乏回归测试手段。

---

## 3. 修复与交付计划 (Remediation Plan)

为了画上完美的句号，Step 10 将集中解决上述“最后一公里”的问题。

### 3.1 任务 1: SPS UDP 支持
*   **目标**: 让 SPS 端口也能处理 UDP 流量。
*   **方案**:
    *   SPS 是基于 TCP 的协议嗅探。对于 UDP，通常不存在“连接”概念，无法像 TCP 那样 Peek 头几个字节。
    *   **策略调整**: 对于 UDP 端口，SPS **无法**做协议嗅探。SPS 的 UDP 端口应默认作为 **SOCKS5 UDP Associate** 的监听端口，或者 SOCKS5 和其他协议需要分开端口监听 UDP。
    *   **实现**: 修改 `sps.NewSPSHandler`，使其返回的 Handler 实现 `UDPConnHandler` 接口（如果存在），并将 UDP 流量默认导向 SOCKS5 Handler（因为 HTTP 不支持 UDP）。

### 3.2 任务 2: Admin API 安全加固
*   **目标**: 保护管理接口。
*   **方案**:
    *   在 `Config` 中增加 `AdminConfig` (Port, Token)。
    *   在 `admin.Server` 中增加中间件，验证 HTTP Header `X-Admin-Token`。

### 3.3 任务 3: 传输层 (Transport) 插件化
*   **目标**: 支持 `SOCKS5+TLS` 或 `SOCKS5+WS`。
*   **方案**:
    *   修改 `ProxyDialer` 的构建逻辑。在解析代理地址 `socks5://user:pass@host:port` 时，允许附加参数 `?transport=tls&tls_server=...`。
    *   或者支持 `tls://host:port` 作为一级代理，内部承载 SOCKS5。

---

## 4. 下一步行动建议

鉴于时间资源，**优先解决 3.2 (Admin 安全) 和 3.1 (SPS UDP)**，这两个是作为“服务”最基本的要求。3.3 和 3.4 可作为 v1.1 版本的迭代目标。

**建议立即执行**:
1.  **Secure Admin**: 为 Admin Server 添加 Token 认证。
2.  **SPS UDP**: 确保 SPS 端口的 UDP 流量能回退到 SOCKS5 处理。
