# NetProxy 架构设计文档

## 1. 项目概述

NetProxy 是一个高性能、多功能、跨平台的网络代理服务软件。旨在提供安全、灵活的网络中转、穿透和代理服务。本项目完全独立设计，旨在实现 GoProxy 文档中描述的所有功能，包括多协议支持、链式代理、内网穿透、负载均衡、高级认证与流控等。

## 2. 需求汇总

根据参考文档，NetProxy 需支持以下核心功能：

*   **多协议支持**: HTTP(S) (正向/反向/透明), SOCKS5, TCP, UDP, SPS (综合协议), Websocket, SS。
*   **网络传输**: 支持 TCP, TLS, KCP, Websocket, SSH 中转。
*   **链式代理**: 支持多级代理跳转，支持异构协议组合。
*   **内网穿透**: 支持 TCP/UDP 穿透，支持多路复用与多连接模式，支持 P2P 打洞。
*   **负载均衡 & 高可用**: 支持上级代理的轮询、最小连接、权重、Hash 等策略。
*   **安全与认证**:
    *   本地/文件认证、远程 API 认证。
    *   流量加密 (TLS, KCP, 自定义 AES-256)。
    *   流量压缩。
    *   访问控制: IP 黑白名单, 域名黑白名单, 端口黑白名单。
*   **流控**: 连接数限制, 速率限制 (用户/IP/端口维度)。
*   **DNS 服务**: 安全 DNS 代理, 缓存, Hosts 支持, 并发解析。
*   **管理与监控**: 流量上报, 动态控制 API, 集群 Agent 模式。

## 3. 系统总架构

NetProxy 采用分层架构与插件化设计，将核心逻辑、协议处理、传输层和扩展功能解耦。

### 3.1 架构图 (Mermaid)

```mermaid
graph TD
    subgraph "Core Layer (核心层)"
        ConfigManager[配置管理]
        Logger[日志系统]
        EventManager[事件总线]
        LifecycleManager[生命周期管理]
    end

    subgraph "Transport Layer (传输层)"
        TransportInterface[传输接口 Abstraction]
        TCPTransport[TCP]
        UDPTransport[UDP]
        TLSTransport[TLS]
        KCPTransport[KCP]
        WSTransport[WebSocket]
        SSHTransport[SSH Tunnel]
    end

    subgraph "Protocol Layer (协议层)"
        HTTPHandler[HTTP/HTTPS Proxy]
        SOCKS5Handler[SOCKS5 Proxy]
        TCPHandler[TCP Proxy]
        UDPHandler[UDP Proxy]
        SPSHandler[SPS Protocol]
        SSHandler[SS Protocol]
        TunnelHandler[Tunnel (Bridge/Server/Client)]
    end

    subgraph "Feature Layer (功能层)"
        AuthModule[认证模块 (Local/API)]
        ACLModule[访问控制 (IP/Domain/Port)]
        Router[路由与链式代理]
        LoadBalancer[负载均衡]
        RateLimiter[流控 (限速/限连)]
        DNSModule[DNS 服务]
        StatsModule[统计与监控]
    end

    subgraph "Service Layer (服务层)"
        ListenerManager[监听管理器]
        ServiceInstance[服务实例]
    end

    ConfigManager --> ListenerManager
    ListenerManager --> ServiceInstance
    ServiceInstance --> ProtocolLayer
    ProtocolLayer --> AuthModule
    ProtocolLayer --> ACLModule
    ProtocolLayer --> Router
    Router --> LoadBalancer
    LoadBalancer --> TransportLayer
    TransportLayer --> RateLimiter
    TransportLayer --> StatsModule

    classDef core fill:#f9f,stroke:#333,stroke-width:2px;
    class ConfigManager,Logger,EventManager,LifecycleManager core;
```

## 4. 模块详细设计

### 4.1 核心层 (Core Layer)

*   **ConfigManager**: 负责解析命令行参数 (Flags) 和配置文件 (TOML/JSON)。支持热加载配置。
*   **LifecycleManager**: 管理服务的启动、停止和优雅关闭。
*   **Logger**: 统一日志接口，支持控制台、文件输出，支持日志级别调整。

### 4.2 传输层 (Transport Layer)

该层封装底层的网络连接，对外提供统一的 `net.Conn` 和 `net.PacketConn` 接口。

*   **设计思路**: 定义 `Transporter` 接口，包含 `Dial` 和 `Listen` 方法。
*   **实现**:
    *   **Raw TCP/UDP**: 基础网络实现。
    *   **TLS**: 封装标准 TLS 库，支持自定义证书加载。
    *   **KCP**: 集成 KCP 协议库，提供基于 UDP 的可靠低延迟传输。
    *   **Websocket**: 将流封装在 WS 协议中，用于穿透防火墙。
    *   **SSH**: 利用 SSH 隧道转发流量。
    *   **自定义加密/压缩**: 实现 `net.Conn` 包装器，在 `Read`/`Write` 中进行透明的 AES 加密或 Snappy/Gzip 压缩。

### 4.3 协议层 (Protocol Layer)

负责应用层协议的解析、握手和数据交换。

*   **HTTP/HTTPS Proxy**:
    *   实现 HTTP 代理标准，处理 `CONNECT` 方法 (HTTPS) 和普通 HTTP 请求。
    *   支持中间人 (MITM) 模式（用于高级功能），或仅透传。
    *   支持反向代理逻辑 (Reverse Proxy)，根据 Host 头分发后端。
*   **SOCKS5**:
    *   完整实现 RFC 1928。支持无需认证和用户/密码认证。
    *   支持 UDP Associate。
*   **SPS (Smart Proxy Service)**:
    *   端口复用技术。在连接建立初期嗅探前几个字节，区分是 HTTP, SOCKS5 还是 SS 协议，动态分发给对应的 Handler 处理。
*   **Tunnel (内网穿透)**:
    *   **Bridge**: 运行在公网，作为中转枢纽，监听控制端口和数据端口。
    *   **Client**: 运行在内网，主动连接 Bridge。
    *   **Server**: 运行在用户端，连接 Bridge，将用户流量转发给 Bridge，Bridge 再通过 Client 转发到内网服务。
    *   **Multiplexing**: 使用多路复用技术 (如 Yamux 或 Smux) 在一条 TCP 连接上承载多个逻辑流。

### 4.4 功能层 (Feature Layer)

横切关注点，为各协议提供通用能力。

*   **Router (路由模块)**:
    *   决定流量是直连 (Direct)、走上级代理 (Parent) 还是拒绝 (Block)。
    *   加载 `blocked`, `direct` 列表文件。
    *   实现“智能模式”：自动检测目标可达性。
*   **LoadBalancer (负载均衡)**:
    *   管理上级代理列表。
    *   实现 RoundRobin, LeastConn, Weight, Hash (Source IP/Target Addr) 算法。
    *   健康检查：定期探测上级代理连通性。
*   **AuthModule (认证)**:
    *   **Local**: 读取用户配置文件。
    *   **API**: 发送 HTTP 请求到远程鉴权服务，缓存结果。
*   **ACLModule (访问控制)**:
    *   CIDR 匹配实现 IP 黑白名单。
    *   基于前缀/后缀/正则的高效域名匹配。
*   **RateLimiter (流控)**:
    *   基于令牌桶 (Token Bucket) 算法实现限速。
    *   计数器实现最大连接数限制。
*   **DNSModule**:
    *   内置 DNS Server (UDP/TCP)。
    *   支持上级 DNS (DoH/DoT)。
    *   Host 映射表。

### 4.5 服务层 (Service Layer)

*   **ListenerManager**:
    *   管理端口监听。支持端口范围 (e.g., `:8000-8010`) 批量监听。
    *   支持端口复用 (SO_REUSEPORT) 或共享 Socket。
    *   将接收到的连接分发给具体的协议 Handler。

## 5. 实现思路关键点

1.  **接口抽象**: 所有的上级代理 (Parent) 都抽象为 `Dialer`，无论是直接连接还是通过 SSH/TLS 连接，对上层协议处理逻辑透明。
2.  **链式代理**: 通过递归或洋葱模型实现。A 连接 B，B 连接 C。在 NetProxy 中，通过将“上级代理”配置为另一个 Proxy 的地址来实现，每一层负责封装自己这一层的协议头。
3.  **内网穿透**: 重点在于 Bridge 端的状态管理。维护 `Client Registry`，当 Server 端有请求时，准确找到对应的 Client 连接会话。P2P 穿透可利用 UDP Hole Punching 技术，尝试让两端直连，失败则回退到 Relay 模式。
4.  **性能优化**:
    *   使用 Buffer Pool 复用内存，减少 GC。
    *   使用 Zero-Copy 技术 (如 `splice` 在 Linux 下) 进行数据转发。
    *   DNS 缓存使用带过期时间的 LRU Cache。
