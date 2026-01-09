# 协议层 (Protocol Layer) 模块文档

## 1. Protocol Handler Interface (协议处理器接口)

### 功能描述
定义处理具体应用层协议的通用接口。每个协议模块（HTTP, SOCKS5 等）都需要实现此接口。

### 接口设计

```go
package protocol

import (
    "context"
    "net"
)

// Handler 处理特定协议的连接
type Handler interface {
    // Handle 处理入站连接
    // conn: 客户端连接
    Handle(ctx context.Context, conn net.Conn) error
}
```

## 2. HTTP/HTTPS Handler

### 功能描述
实现标准的 HTTP 代理和 HTTPS (CONNECT) 隧道。

### 主要逻辑
1.  **Request Parsing**: 读取连接的前几个字节，解析 HTTP Method 和 URL。
2.  **CONNECT Handling (HTTPS)**:
    *   如果 Method 是 `CONNECT`，则从 URL 获取目标 `Host:Port`。
    *   进行权限检查 (Auth/ACL)。
    *   连接目标服务器。
    *   向客户端发送 `200 OK`。
    *   进入双向流转发模式 (Tunneling)。
3.  **Regular HTTP Handling**:
    *   如果 Method 是 GET/POST 等，解析绝对 URL 或 Host 头获取目标。
    *   进行权限检查。
    *   连接目标服务器。
    *   将客户端请求转发给目标（可能需要修改 Proxy-Connection 等 Header）。
    *   将目标响应转发回客户端。
4.  **MITM (Optional)**: 如果配置了中间人解密，则在 CONNECT 握手后，伪造证书与客户端建立 TLS 连接，解密流量后再发起对目标的请求。

## 3. SOCKS5 Handler

### 功能描述
实现 RFC 1928 SOCKS Protocol Version 5 标准。

### 主要逻辑
1.  **Negotiation (协商)**: 读取版本号 (0x05) 和支持的认证方法列表。返回选定的认证方法（无需认证 / 用户名密码）。
2.  **Authentication (认证)**: 如果需要，执行 RFC 1929 用户名密码认证。
3.  **Request (请求)**: 读取客户端请求（CMD, ATYP, DST.ADDR, DST.PORT）。
    *   CMD: CONNECT (TCP), BIND (FTP), UDP ASSOCIATE.
4.  **Connect (TCP)**: 解析目标地址，连接目标，返回响应，进入流转发。
5.  **UDP Associate**:
    *   分配一个 UDP 端口监听。
    *   将监听地址返回给客户端。
    *   处理 UDP 转发：读取客户端发来的 UDP 包（带头部），解包后发往目标；接收目标 UDP 包，封装头部发回客户端。

## 4. SPS Handler (Smart Proxy Service)

### 功能描述
智能协议识别。在一个端口上同时支持 HTTP, SOCKS5, SS 等多种协议。

### 主要逻辑
1.  **Sniffing (嗅探)**: 读取连接的前几个字节（Peek，不消耗）。
2.  **Matching (匹配)**:
    *   如果首字节是 `0x05` -> SOCKS5。
    *   如果前几个字节匹配 HTTP Methods (GET, POST, CONNECT...) -> HTTP。
    *   其他情况 -> 尝试作为 SS 或自定义协议处理，或者回退到默认协议。
3.  **Dispatch (分发)**: 根据匹配结果，将 `net.Conn` 转交给对应的 Handler 处理。注意需要处理 Peek 读取过的字节，确保后续 Handler 能读到完整流（可使用 `io.MultiReader` 或自定义 BufferedConn）。

## 5. Tunnel Handler (内网穿透)

### 功能描述
实现内网穿透的 Bridge, Server, Client 组件。

### 架构设计
*   **Bridge (公网)**: 监听 Control Port 和 Data Port。
*   **Client (内网)**: 连接 Bridge 的 Control Port，保持长连接。
*   **Server (用户端)**: 连接 Bridge 的 Data Port。

### 主要逻辑
1.  **Session Management**: Bridge 维护 Client ID 到 Control Conn 的映射。
2.  **Multiplexing**: 使用 Yamux/Smux 在 Control Conn 上复用流。
3.  **Workflow**:
    *   Server 连接 Bridge (Data Port)。
    *   Bridge 暂停 Server 连接，通过 Control Conn 向 Client 发送 "New Connection" 信号。
    *   Client 收到信号，发起一个新的逻辑流 (Stream) 连接到 Bridge，并同时连接内网目标服务。
    *   Bridge 将 Server 连接与 Client 新建的 Stream 对接 (Join)，开始转发数据。

## 6. SS Handler (Shadowsocks)

### 功能描述
实现 Shadowsocks 协议，兼容标准客户端。

### 主要逻辑
1.  **Cipher**: 初始化 AEAD 加密器 (e.g., chacha20-poly1305)。
2.  **Handshake**: 读取加密的盐值 (Salt)。
3.  **Decryption**: 建立加密流 Reader，读取并解密目标地址。
4.  **Forwarding**: 连接目标，双向转发加密数据。

## 7. TCP/UDP Handler (Port Forwarding)

### 功能描述
基础的端口转发（四层代理）。

### 主要逻辑
*   **Static**: 配置固定的目标地址 (e.g., Listen :80 -> Forward 192.168.1.1:80)。
*   **Transparent**: 读取 socket 的原始目标地址 (SO_ORIGINAL_DST)，实现透明代理。
