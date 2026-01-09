# NetProxy 功能完善度分析与实现文档

## 1. 现状分析

通过对现有代码库的审查，NetProxy 目前已实现了核心架构框架和部分基础功能，但距离功能完整的代理服务软件仍有一定差距。

### 已实现功能 (Implemented)

*   **架构框架**:
    *   分层架构（核心层、传输层、协议层、功能层、服务层）已搭建。
    *   `ListenerManager`、`ServiceInstance` 等核心组件已定义。
    *   `ConfigManager` (Viper) 支持配置文件加载和热更新。
    *   `Logger` (Zap wrapper) 基础实现。
*   **传输层 (Transport)**:
    *   `TCP`, `UDP` 基础传输实现。
    *   `TLS` 支持证书加载。
    *   `KCP` (集成 kcp-go) 基础支持。
    *   `WebSocket` (集成 gorilla/websocket) 基础支持。
    *   `SSH` 隧道基础支持。
*   **协议层 (Protocol)**:
    *   `HTTP` (基于 goproxy) 基础代理逻辑。
    *   `SOCKS5` (基于 go-socks5) 基础代理逻辑。
    *   `TCP` 端口转发。
    *   `UDP` 端口转发 (基础 io.Copy)。
    *   `SPS` (Smart Proxy Service) 实现了基础的协议嗅探和分发逻辑。
*   **功能层 (Feature)**:
    *   `ACL` (Simple) 基于 IP 和 Host 的简单黑白名单。
    *   `Auth` (Local) 简单的 Map 基于用户名密码认证。
    *   `RateLimit` (TokenBucket) 基于令牌桶的限速。
    *   `Stats` (Simple) 基础的连接数和流量统计。
    *   `DNS` (Simple) 简单的 DNS 转发服务器。
    *   `Router` (Simple) 基础的 Direct/Block/Proxy 路由逻辑。
    *   `LoadBalancer` (RoundRobin, Random) 基础负载均衡算法。

### 欠缺功能 (Missing) & 待完善点 (To Be Improved)

1.  **链式代理 (Chain Proxy)**:
    *   **状态**: 未实现。
    *   **缺失**: 目前 `Router` 仅支持简单的下一跳选择，不支持多级代理跳转（A -> B -> C -> Target）。
    *   **需求**: 需要定义代理链结构，每一层代理负责封装自己的协议头。

2.  **内网穿透 (Tunnel)**:
    *   **状态**: 未实现。
    *   **缺失**: `Bridge` (服务端), `Client` (内网端), `Server` (用户端) 的完整交互逻辑缺失。
    *   **需求**: 需要实现 Control 通道管理、多路复用 (Yamux/Smux)、反向连接建立。

3.  **高级认证与安全**:
    *   **状态**: 基础。
    *   **缺失**: 远程 API 认证、流量加密 (自定义 AES-256)、流量压缩 (Snappy/Gzip)。
    *   **需求**: 扩展 `AuthModule` 支持 HTTP API；实现 `Transport` 层的加密/压缩 Wrapper。

4.  **完整的多协议支持细节**:
    *   **HTTP**: 缺少反向代理的高级配置（Host 路由分发）。
    *   **SOCKS5**: 缺少 UDP Associate 的完整自定义实现（目前依赖库，灵活性不足）。
    *   **SS (Shadowsocks)**: 代码中仅有相关文档提及，未见具体实现。
    *   **UDP**: 目前的 UDP Handler 比较简单，对于复杂的 UDP 代理（如游戏加速）可能不足。

5.  **高级路由与策略**:
    *   **状态**: 简单。
    *   **缺失**: 基于 GeoIP 的路由、外部规则集 (GFWList) 加载、自动测速选择最优路径。

6.  **管理与监控 API**:
    *   **状态**: 缺失。
    *   **需求**: 需要提供 HTTP API 用于动态查看状态、踢出用户、热更配置等。

---

## 2. 实现文档 (realized_step2.md)

以下文档将指导下一步的开发工作，重点补全上述缺失的核心功能。

### 2.1 任务 1: 实现链式代理 (Chained Proxy)

**目标**: 允许流量经过多个代理节点到达目标。

**实现思路**:
1.  **修改 `Router`**:
    *   在 `RouteResult` 中增加 `NextHops []string` 字段，表示一串代理节点。
    *   支持配置文件定义 `Chains`。
2.  **抽象 `Dialer`**:
    *   创建一个 `ProxyDialer` 接口。
    *   实现 `SOCKS5Dialer`, `HTTPDialer`, `SSDialer`。
    *   **嵌套**: 一个 Dialer 可以包含另一个 Dialer。例如 `SOCKS5Dialer(HTTPDialer(DirectDialer))` 表示先连 HTTP 代理，再在里面握手 SOCKS5。
3.  **集成**:
    *   在 `ServiceInstance` 处理连接时，根据 `Router` 返回的链，动态构建嵌套的 `Dialer` 链，最终建立到目标的连接。

### 2.2 任务 2: 实现内网穿透 (Tunnel Module)

**目标**: 实现内网服务暴露到公网。

**文件**: 新建 `internal/protocol/tunnel/`

**实现思路**:
1.  **Bridge (公网服务端)**:
    *   监听 `ControlPort` (TCP) 和 `DataPort` (User Entry)。
    *   维护 `ClientRegistry` (Map[ClientID] -> ControlConn)。
    *   使用 `yamux` 在 ControlConn 上复用流。
2.  **Client (内网客户端)**:
    *   主动 Dial Bridge 的 `ControlPort`。
    *   监听 ControlConn 上的指令流。
    *   收到 "NewConn" 指令时，Dial 本地目标服务 (LocalTarget)，同时在 ControlConn 上 Open 一个新 Stream，将两者 Bridge 起来。
    *   **优化**: 为了更高性能，可以不复用 ControlConn 传输数据，而是收到指令后，Client 主动发起一个新的 TCP 连接到 Bridge 的 `DataPort` (带上 ID)，由 Bridge 进行拼接。
3.  **协议设计**:
    *   定义简单的控制指令：`CONNECT <req_id> <target>`, `PING`, `PONG`。

### 2.3 任务 3: 完善高级认证与流量处理

**目标**: 增强安全性和灵活性。

**实现思路**:
1.  **API Auth**:
    *   在 `internal/feature/auth` 中实现 `HTTPAuthenticator`。
    *   发送 POST 请求到配置的 URL，携带 User/Pass，根据响应状态码判断成功失败。
    *   增加 `LRU Cache` 缓存认证结果，避免频繁请求。
2.  **Crypto Transport Wrapper**:
    *   在 `internal/transport/crypto` 中实现。
    *   `NewCryptoConn(conn net.Conn, key string)`.
    *   使用 `AES-256-CFB` 或 `Chacha20` 包装 Read/Write。
3.  **Compression Wrapper**:
    *   使用 `snappy` 包装 `net.Conn`。

### 2.4 任务 4: 补充 SS (Shadowsocks) 协议支持

**目标**: 支持 SS 协议的入站和出站。

**实现思路**:
1.  **依赖**: `github.com/shadowsocks/go-shadowsocks2/core`
2.  **Handler**:
    *   `internal/protocol/ss/handler.go`: 实现 `protocol.Handler`。
    *   读取 Salt，初始化 Cipher，解密读取 Target Address，连接并转发。
3.  **Transport**:
    *   实现 `SSTransport` (作为 Dialer)，用于链式代理的中间环节。

### 2.5 任务 5: 管理 API (Management API)

**目标**: 运行时监控与控制。

**实现思路**:
1.  **HTTP Server**: 在 `internal/core/admin` 中启动一个独立的 HTTP Server (e.g., :9090)。
2.  **Endpoints**:
    *   `GET /stats`: 返回 `StatsModule` 的 JSON 数据。
    *   `GET /conns`: 列出当前活跃连接 (需要 `ServiceInstance` 注册连接到全局 Manager)。
    *   `POST /conns/{id}/kill`: 强制断开指定连接。
    *   `POST /config/reload`: 触发 `ConfigManager.Reload()`。

## 3. 下一步执行计划 (Action Plan)

建议按以下顺序执行：

1.  **完善 SS 协议**: 这是基础协议支持的缺失，优先级高。
2.  **实现链式代理**: 增强核心路由能力。
3.  **实现内网穿透**: 这是一个较大的独立模块，增加核心卖点。
4.  **增强认证与加密**: 完善安全特性。
5.  **添加管理 API**: 提升运维体验。
