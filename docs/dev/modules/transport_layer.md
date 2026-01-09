# 传输层 (Transport Layer) 模块文档

## 1. Transport Interface (传输接口抽象)

### 功能描述
定义统一的网络传输接口，屏蔽底层具体的协议实现（TCP, UDP, KCP, WS, SSH, TLS），使得上层协议处理逻辑（如 HTTP, SOCKS5）与底层传输方式解耦。

### 接口设计

```go
package transport

import (
    "context"
    "net"
)

// Transporter 定义传输层通用行为
type Transporter interface {
    // Dial 建立连接
    Dial(ctx context.Context, addr string) (net.Conn, error)
    
    // Listen 监听地址
    Listen(ctx context.Context, addr string) (net.Listener, error)
    
    // ListenPacket 监听数据报 (UDP/KCP)
    ListenPacket(ctx context.Context, addr string) (net.PacketConn, error)
}

// Factory 用于根据协议名称创建 Transporter
type Factory func(options interface{}) Transporter
```

### 主要逻辑
1.  **Registry**: 维护一个 `map[string]Factory`，用于通过配置动态实例化不同的 Transporter。
2.  **Wrapper**: 可以对 `net.Conn` 进行包装，例如在 Read/Write 操作中增加统计计数、限速逻辑或透明加密。

## 2. TCPTransport

### 功能描述
基于标准 TCP 协议的传输实现。

### 主要逻辑
*   **Dial**: 封装 `net.Dialer`，支持超时设置、KeepAlive 设置。
*   **Listen**: 封装 `net.Listen`。
*   **优化**: 可设置 TCP_NODELAY 等 Socket 选项。

## 3. UDPTransport

### 功能描述
基于标准 UDP 协议的传输实现。

### 主要逻辑
*   **无连接**: UDP 是无连接的，但在代理场景中，通常需要维护一个虚拟的“会话”映射（NatTable），将 UDP 包关联到特定的源 IP:Port，以便处理回包。
*   **Timeout**: 设置 ReadDeadline，定期清理空闲的 UDP 会话。

## 4. TLSTransport

### 功能描述
基于 TLS (Transport Layer Security) 的安全传输实现。

### 接口设计
配置结构需包含证书路径、Key 路径、CA 证书路径、InsecureSkipVerify 等。

### 主要逻辑
*   **Dial**: 使用 `tls.Dial`。
*   **Listen**: 使用 `tls.NewListener` 包装下层的 TCP Listener。
*   **证书管理**: 支持从 ConfigManager 加载证书，或从 FeatureLayer 的证书管理器获取动态证书。

## 5. KCPTransport

### 功能描述
集成 KCP 协议，提供弱网环境下的可靠低延迟传输。

### 依赖库
`github.com/xtaci/kcp-go`

### 主要逻辑
*   **参数调优**: 暴露 KCP 关键参数（sndwnd, rcvwnd, mtu, nodelay, interval, resend, nc）到配置文件。
*   **FEC**: 支持前向纠错配置。
*   **加密**: 集成 KCP 内置的加密层（AES/Blowfish/Twofish 等）。

## 6. WSTransport (WebSocket)

### 功能描述
将 TCP 流封装在 WebSocket 协议中，用于通过 HTTP 代理或 CDN 传输数据，绕过防火墙对非 HTTP 流量的限制。

### 依赖库
`github.com/gorilla/websocket`

### 主要逻辑
*   **握手**: 发起标准的 HTTP Upgrade 请求。
*   **Framing**: 将 `net.Conn.Write` 的数据封装为 Binary Message 发送；接收 Binary Message 并解包供 `net.Conn.Read` 读取。
*   **Path**: 支持配置 WebSocket Path。

## 7. SSHTransport (SSH Tunnel)

### 功能描述
利用 SSH 协议建立加密隧道，作为传输载体。

### 依赖库
`golang.org/x/crypto/ssh`

### 主要逻辑
*   **Client**: 建立 SSH Client 连接，通过 `sshClient.Dial` 创建流。
*   **Server**: 运行 SSH Server，接收连接请求。
*   **认证**: 支持密码认证和公钥认证。

## 8. CustomCryptoTransport (自定义加密)

### 功能描述
一个装饰器 Transport，在任何底层 `net.Conn` 之上增加一层轻量级加密（如 XOR, AES-CTR），用于简单的流量混淆。

### 主要逻辑
*   实现 `net.Conn` 接口。
*   `Read(b []byte)`: 先调用 underlying.Read(b)，然后解密 b。
*   `Write(b []byte)`: 先加密 b，然后调用 underlying.Write(encrypted)。
