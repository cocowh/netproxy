# 服务层 (Service Layer) 模块文档

## 1. ListenerManager (监听管理器)

### 功能描述
负责所有入口连接的监听管理。它解析配置，启动相应的网络监听器（TCP, UDP, KCP, etc.），并将接收到的连接分发给 ServiceInstance。

### 接口设计

```go
package listener

// Manager 监听管理器接口
type Manager interface {
    // Start 启动所有监听器
    Start(ctx context.Context) error
    
    // Stop 停止所有监听器
    Stop(ctx context.Context) error
    
    // Refresh 热更新监听配置（增量启动/关闭）
    Refresh(configs []ListenerConfig) error
}

// ListenerConfig 监听配置
type ListenerConfig struct {
    Protocol string // tcp, udp, kcp, ws, tls
    Addr     string // :8080
    Options  map[string]interface{} // certs, kcp params...
}
```

### 主要逻辑
1.  **Multiple Protocols**: 根据配置的 Protocol 字段，调用 TransportLayer 的 Factory 创建对应的 `net.Listener` 或 `net.PacketConn`。
2.  **Port Range**: 支持端口范围配置 (e.g., `:10000-10010`)。如果是范围，则循环创建多个 Listener。
3.  **Graceful Restart**: 在 `Refresh` 时，对比新旧配置。
    *   新增的：启动。
    *   删除的：关闭。
    *   修改的：重启（关闭旧的启动新的）。
    *   不变的：保持运行。
4.  **Accept Loop**: 为每个 Listener 启动一个 goroutine 进行 Accept，获取 `net.Conn` 后传递给 `ServiceInstance.HandleConn`。

## 2. ServiceInstance (服务实例)

### 功能描述
代表一个具体的代理服务实体。它将 Transport, Protocol, Feature 层的能力串联起来，处理单次连接的完整生命周期。

### 接口设计

```go
package instance

// Instance 服务实例接口
type Instance interface {
    // HandleConn 处理一个新的传输层连接
    HandleConn(ctx context.Context, conn net.Conn)
}
```

### 主要逻辑 (Connection Lifecycle)
1.  **Init**: 接收 `net.Conn`。
2.  **Metadata**: 提取元数据（ClientIP, LocalAddr）。生成唯一的 RequestID。
3.  **Feature Filters (Pre-Handshake)**:
    *   **RateLimit**: 检查最大连接数限制。
    *   **IP Filter**: 检查 IP 黑名单。
    *   如果不通过，直接 Close。
4.  **Protocol Handshake**:
    *   根据配置（如 SOCKS5, HTTP），调用对应的 Protocol Handler 进行握手。
    *   如果是 SPS (Smart Proxy)，先进行嗅探再分发。
5.  **Authentication**: 在协议握手过程中或之后，调用 AuthModule 进行认证。
6.  **Routing**:
    *   解析出目标地址 (Target Address)。
    *   调用 Router 模块决定路由策略 (Direct/Proxy/Block)。
7.  **Upstream Connection**:
    *   根据路由结果，使用 TransportLayer 建立到目标（或上级代理）的连接。
8.  **Data Forwarding**:
    *   建立双向数据管道 (Pipe/Copy)。
    *   在转发过程中，应用速率限制 (RateLimiter) 和流量统计 (StatsModule)。
9.  **Cleanup**:
    *   连接断开（正常结束或错误）。
    *   释放资源，更新统计数据。

## 3. Server (主服务入口)

### 功能描述
整个应用程序的根对象，组装 ConfigManager, ListenerManager, ServiceInstance 等组件。

### 主要逻辑
1.  **Bootstrap**: `main` 函数调用的入口。
2.  **Dependency Wiring**: 初始化各个 Manager，注入依赖关系。
3.  **Signal Handling**: 监听退出信号，通知 LifecycleManager 执行关闭流程。
