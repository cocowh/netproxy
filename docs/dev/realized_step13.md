# NetProxy UDP 协议栈重构与工程化完善计划 (Step 13)

## 1. 现状综述 (Status Overview)

经过 Step 12 的开发与深度审计，NetProxy 在 TCP 协议层面的功能已趋于成熟，支持了复杂的链式代理、智能路由和内网穿透。然而，在 **UDP 协议栈** 的实现上，暴露出严重的工程化缺陷。

虽然代码库中存在 UDP 相关的逻辑（如 `socks5/udp.go`, `transport/udp.go`），但这些实现大多处于“原型验证”阶段，存在架构上的阻断点和严重的性能隐患，导致 UDP 功能（DNS 代理、QUIC 支持、游戏加速等）在实际生产环境中完全不可用。

本文档旨在详细记录这些缺陷，并制定 Step 13 的修复计划，重点在于**重构 UDP 监听与转发机制**，使其达到生产级标准。

---

## 2. 核心缺陷分析 (Critical Defects Analysis)

### 2.1 架构缺陷：ListenerManager 不支持 UDP 监听
*   **问题描述**: `internal/service/listener` 模块的设计完全基于 TCP 流模型 (`net.Listener` + `Accept()`)。Step 12 尝试在 `main.go` 中通过配置启动 UDP 监听，但底层的 `transport/udp.go` 明确返回错误 `udp does not support Listen`。
*   **根本原因**: UDP 是无连接的，没有 `Accept` 概念，对应的是 `ListenPacket` 和 `ReadFrom/WriteTo` 模型。现有的 `ListenerManager` 接口无法兼容这种差异。
*   **影响**: SPS (Smart Proxy Service) 端口无法同时监听 TCP 和 UDP，导致 SOCKS5 UDP Associate 功能在 SPS 模式下失效。

### 2.2 性能缺陷：SOCKS5 UDP Relay 资源泄漏
*   **问题描述**: `internal/protocol/socks5/udp.go` 中的 `runUDPRelay` 实现极其低效。它为**每一个**接收到的 UDP 数据包启动一个新的 Goroutine，并建立一个新的上游连接 (`DialPacket`)。
*   **代码证据**:
    ```go
    // internal/protocol/socks5/udp.go
    go func(...) {
        upstream, _ := dialer.DialPacket(...) // 每包一次 Dial
        upstream.WriteTo(...)
    }(...)
    ```
*   **后果**:
    *   **性能崩溃**: 高吞吐量场景下（如视频流、QUIC），Goroutine 数量瞬间爆炸，CPU 和内存耗尽。
    *   **NAT 穿透失败**: 由于每次发送都使用新的随机源端口，无法保持 NAT 会话，导致上游回包无法正确路由回来（Symmetric NAT 问题）。

### 2.3 可用性缺陷：绑定地址 (BND.ADDR) 不可达
*   **问题描述**: SOCKS5 UDP Associate 响应中返回的 `BND.ADDR` 是 `0.0.0.0` (由 `net.ListenPacket("udp", ":0")` 产生)。
*   **影响**: 客户端（Client）收到 `0.0.0.0` 后，无法向该地址发送 UDP 数据包（特别是在 Docker 或 NAT 环境下）。必须返回外部可达的 IP 地址（Public IP 或 LAN IP）。

### 2.4 接口缺陷：Handler 接口不兼容 Packet
*   **问题描述**: `internal/protocol/interface.go` 中的 `Handler` 接口仅定义了 `Handle(ctx, conn net.Conn) error`。
*   **影响**: 该接口无法处理 UDP 的 `net.PacketConn`。如果强行将 PacketConn 包装成 Conn，会丢失 UDP 特有的“目标地址”上下文，或者导致逻辑混乱。

---

## 3. 修复与重构计划 (Remediation Plan)

Step 13 将聚焦于**打通 UDP 全链路**，确保其性能和可用性。

### 3.1 任务 1: 重构 ListenerManager
**目标**: 使服务层同时支持 Stream (TCP) 和 Packet (UDP) 监听。

*   **修改**:
    *   扩展 `listener.ListenerConfig`，明确区分 `Network` (tcp/udp)。
    *   修改 `listener.Manager`，增加对 `net.PacketConn` 的管理能力。
    *   引入 `PacketHandler` 接口，用于处理无连接数据包。

### 3.2 任务 2: 重写 SOCKS5 UDP Relay (NAT Table)
**目标**: 实现高效、正确的 UDP 转发。

*   **实现思路**: 引入 **Session Table (NAT 映射表)**。
    *   **Key**: `ClientIP:ClientPort <-> TargetIP:TargetPort`
    *   **Value**: 复用的上游 `PacketConn`。
*   **逻辑**:
    1.  收到 UDP 包，查询 Session 表。
    2.  若命中，直接使用现有的上游 Conn 转发。
    3.  若未命中，创建新的上游 Conn，记录到表中，并启动**该 Session 专属**的读取循环（处理回包）。
    4.  引入空闲超时机制 (Idle Timeout)，清理不活跃的 Session。

### 3.3 任务 3: 扩展 Protocol 接口
**目标**: 统一协议层接口。

*   **修改**:
    ```go
    type Handler interface {
        Handle(ctx context.Context, conn net.Conn) error
    }
    
    // 新增 PacketHandler 接口
    type PacketHandler interface {
        HandlePacket(ctx context.Context, conn net.PacketConn) error
    }
    ```
*   让 `socks5Handler` 和 `spsHandler` 同时实现这两个接口。

### 3.4 任务 4: 修复绑定地址问题
**目标**: 支持配置外部 IP。

*   **配置增强**: 在 `ListenerConfig` 中增加 `AnnounceAddr` 字段。
*   **逻辑**: SOCKS5 UDP Associate 阶段，优先使用配置的 `AnnounceAddr` 作为 `BND.ADDR` 返回给客户端。

---

## 4. 预期结果

完成 Step 13 后，NetProxy 将具备：
1.  **真正的 UDP 支持**: SPS 端口可同时处理 TCP/UDP。
2.  **高性能转发**: UDP 转发不再泄漏资源，支持高并发。
3.  **NAT 兼容性**: 能够正确穿透 NAT 环境，支持 WebRTC 和 QUIC。
