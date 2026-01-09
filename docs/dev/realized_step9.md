# NetProxy 核心网络能力与路由引擎升级 (Step 9)

## 1. 目标 (Goal)

基于 Step 8 的审计报告，本阶段将集中解决**核心网络能力缺失**和**路由模块性能瓶颈**两个最关键的问题。具体目标如下：

1.  **全链路 UDP 支持**: 打通从入口 (SOCKS5 UDP Associate) 到出口 (Direct/Proxy UDP) 的 UDP 数据通路，为 DNS 查询和 QUIC/WebRTC 流量提供支持。
2.  **高性能路由引擎**: 引入 Trie (基数树) 和 CIDR (无类别域间路由) 匹配算法，提升路由匹配效率至 O(1) / O(logN) 级别，并支持 IP 段匹配。
3.  **工程化重构**: 优化 `main.go` 的配置加载逻辑，消除硬编码解析。

## 2. 详细设计 (Detailed Design)

### 2.1 网络层接口升级 (Network Layer)

**文件**: `internal/transport/interface.go`, `internal/transport/proxy_dialer.go`

*   **`Transporter` 接口变更**:
    *   新增 `DialPacket(ctx context.Context, addr string) (net.PacketConn, error)` 方法，用于创建 UDP 连接。
*   **`ProxyDialer` 接口变更**:
    *   新增 `DialPacket` 方法，允许通过代理服务器建立 UDP 会话。

### 2.2 SOCKS5 UDP Associate 实现

**文件**: `internal/protocol/socks5/socks5.go`, `internal/protocol/socks5/udp.go` (新建)

*   **信令交互**: 实现 SOCKS5 `UDP ASSOCIATE` 命令的处理逻辑。
*   **数据转发**:
    *   建立 UDP 监听端口（动态或配置指定）。
    *   封装/解封装 SOCKS5 UDP 头部 (RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA)。
    *   通过 `SmartDialer` 将解包后的 UDP 数据包转发至目标。

### 2.3 智能路由 (SmartDialer) UDP 适配

**文件**: `internal/transport/smart_dialer.go`

*   实现 `DialPacket` 方法。
*   在该方法中复用路由匹配逻辑 (`router.Match`)。
*   根据匹配结果（Direct, Proxy, Block），选择相应的出口策略：
    *   **Direct**: 直接使用 `net.ListenPacket` 或 `net.DialUDP`。
    *   **Proxy**: 暂不支持通过 TCP 隧道转发 UDP (SOCKS5 over TCP)，本阶段仅支持直连 UDP 或 SOCKS5 UDP (如果上游支持)。鉴于 Step 8 提到上游传输层受限，我们优先实现 Direct UDP 和基础的 Proxy UDP (如果有实现)。*注：完整 UDP over TCP/TLS 隧道可能涉及复杂协议封装，本阶段优先保障 Direct UDP 可用。*

### 2.4 路由引擎重构 (Router Engine)

**文件**: `internal/feature/router/router.go`, `internal/feature/router/trie.go` (新建), `internal/feature/router/cidr.go` (新建)

*   **数据结构升级**:
    *   域名匹配：使用 **Radix Tree (Trie)** 替代简单的字符串切片遍历。支持通配符 (`*.google.com`) 高效查找。
    *   IP 匹配：使用 **CIDR Trie** 或 **Interval Tree** 支持 `192.168.1.0/24` 格式的快速匹配。
*   **配置解析优化**:
    *   支持 `cidr:10.0.0.0/8` 语法。

### 2.5 配置加载重构

**文件**: `cmd/netproxy/main.go`, `internal/core/config/parser.go` (新建)

*   将 `main.go` 中手动的 `proxy: domain:...` 字符串切割逻辑移至 `internal/core/config` 包下的辅助函数中。

## 3. 实施步骤 (Implementation Steps)

1.  **基础设施**: 更新 `transport` 接口定义。
2.  **路由升级**: 实现 Trie 和 CIDR 数据结构，并替换 `SimpleRouter` 内部实现。
3.  **UDP 核心**: 实现 `SmartDialer.DialPacket`。
4.  **协议接入**: 实现 SOCKS5 `UDP ASSOCIATE` 逻辑。
5.  **重构**: 清理 `main.go`。

