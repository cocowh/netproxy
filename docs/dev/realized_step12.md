# NetProxy 缺陷修复与稳定性提升计划 (Step 12)

## 1. 背景 (Background)

基于对项目代码的深度审计（Step 11 之后），我们识别出了阻碍 NetProxy 达到“生产级”标准的 4 个关键缺陷。这些缺陷主要涉及网络层的完整性、协议的兼容性以及系统的安全性。本阶段的目标是集中修复这些问题，确保核心功能的稳健。

## 2. 待修复缺陷列表 (Defect List)

### 2.1 核心网络能力缺陷：UDP over TLS/WS 链路中断 (Critical)
*   **问题**: `TLSDialer` 和 `WSDialer` 的 `DialPacket` 方法目前直接返回不支持错误。这导致配置为 TLS 或 WebSocket 传输模式的上游代理无法处理 UDP 流量（如 DNS 查询、QUIC）。
*   **影响**: 安全传输模式下，SOCKS5 UDP Associate 功能失效。

### 2.2 SPS 协议 UDP 支持缺失 (Major)
*   **问题**: SPS (Smart Proxy Service) 端口在启动监听时仅绑定了 TCP，未绑定 UDP。尽管 Handler 层有 UDP 判断逻辑，但物理上无法接收 UDP 包。
*   **影响**: SPS 端口无法作为 SOCKS5 UDP Associate 的监听端口。

### 2.3 路由策略硬编码 (Major)
*   **问题**: `SimpleRouter` 在处理域名匹配的 Proxy 动作时，硬编码了 `https://8.8.8.8/dns-query` 作为上游 DNS。
*   **影响**: 国内环境可用性差，用户无法自定义 DNS 策略。

### 2.4 Admin 服务安全隐患 (Security)
*   **问题**: Admin Server 强制监听 `0.0.0.0`，无法配置仅绑定 `127.0.0.1`。
*   **影响**: 增加了公网部署时的受攻击面。

---

## 3. 执行任务 (Execution Tasks)

### Task 1: 实现 UDP over TLS/WS
**目标**: 打通安全传输层下的 UDP 通路。

**实现思路**:
*   **原理**: 由于 TLS/WS 本质是 TCP 流，需要将 UDP 数据包封装在流中传输。
*   **WSDialer**: 利用 WebSocket 的 Binary Message 传输 UDP 包。
*   **TLSDialer**: 定义简单的长度前缀协议（Length-Prefixed），在 TLS 流中通过 `[Length][Body]` 的方式传输 UDP 包。
*   **Action**: 修改 `internal/transport/ws_dialer.go` 和 `tls_dialer.go`，实现 `DialPacket` 方法，返回一个封装了流传输逻辑的 `net.PacketConn`。

### Task 2: 完善 SPS 端口的 UDP 监听
**目标**: 让 SPS 端口能同时处理 TCP 和 UDP。

**实现思路**:
1.  **修改 `cmd/netproxy/main.go`**: 在启动 Listener 时，如果协议是 `sps` 或 `mixed`，除了启动 `net.Listen` (TCP) 外，还需要启动 `net.ListenPacket` (UDP)。
2.  **UDP 分发**: 接收到的 UDP 包应直接交给 `SOCKS5` 的 UDP Handler 处理（因为 HTTP 不支持 UDP）。
3.  **生命周期管理**: 确保 UDP Listener 也能随服务关闭而关闭。

### Task 3: 消除路由硬编码
**目标**: 允许配置远程 DNS。

**实现思路**:
1.  **Config**: 在 `RoutingConfig` 中增加 `RemoteDNS` 字段 (e.g., "https://1.1.1.1/dns-query")。
2.  **Router**: 修改 `MatchDomain`，读取配置中的 DNS 地址，而不是硬编码 `8.8.8.8`。如果配置为空，则提供合理的默认值或回退策略。

### Task 4: Admin 接口绑定地址配置
**目标**: 限制 Admin 监听地址。

**实现思路**:
1.  **Config**: 修改 `AdminConfig`，将 `Port` 改为 `Addr` (string) 或者增加 `BindIP`。建议改为 `ListenAddr` (e.g., "127.0.0.1:9090")。
2.  **Main**: 使用配置的完整地址启动 Admin Server。

## 4. 建议执行顺序
1.  **Task 3 & 4** (配置与路由修复): 风险低，收益明确，先解决。
2.  **Task 2** (SPS UDP): 涉及启动逻辑修改。
3.  **Task 1** (Transport UDP): 涉及较复杂的流封装逻辑，最后攻坚。
