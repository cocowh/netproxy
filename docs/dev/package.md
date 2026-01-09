# 项目依赖库调研与选型

根据 NetProxy 的架构设计与功能需求，以下是推荐使用的 Go 语言相关依赖库。这些库在社区中活跃度高、性能优秀且经过生产环境验证。同时，我们也检查了这些库的开源许可证（License），确保它们与本项目的 MIT License 兼容。

**License 兼容性说明**:
*   ✅ **MIT / BSD / Apache 2.0 / ISC**: 完全兼容，可放心使用。
*   ⚠️ **MPL 2.0**: 弱 Copyleft 协议。作为依赖库链接使用是兼容的（只要不修改库本身的源码），但如果需要更严格的 MIT 纯度，可选择替代方案。

## 1. 核心层 (Core Layer)

### 1.1 配置管理 (Config)
*   **库名**: `github.com/spf13/viper`
*   **License**: ✅ MIT
*   **用途**: 处理 JSON/TOML/YAML 等多种格式的配置文件，支持环境变量覆盖和命令行标志绑定。
*   **理由**: Go 生态中最流行的配置管理库，功能全面，支持热加载。

### 1.2 命令行工具 (CLI)
*   **库名**: `github.com/spf13/cobra`
*   **License**: ✅ Apache 2.0
*   **用途**: 构建强大的 CLI 应用程序，生成命令结构。
*   **理由**: 与 Viper 配合完美，是 Kubernetes 等大型项目的标准选择。

### 1.3 日志系统 (Logger)
*   **库名**: `go.uber.org/zap`
*   **License**: ✅ MIT
*   **用途**: 高性能、结构化的日志记录。
*   **理由**: 相比 Logrus，Zap 提供极高的性能和低内存分配，非常适合网络代理这种高吞吐场景。

### 1.4 依赖注入 (可选)
*   **库名**: `go.uber.org/fx` 或 `github.com/google/wire`
*   **License**: ✅ MIT (Fx) / ✅ Apache 2.0 (Wire)
*   **用途**: 管理组件生命周期和依赖关系。
*   **理由**: 随着模块增多，手动组装依赖会变得复杂，FX 提供了一个优雅的生命周期管理框架。

## 2. 传输层 (Transport Layer)

### 2.1 KCP 协议
*   **库名**: `github.com/xtaci/kcp-go`
*   **License**: ✅ MIT
*   **用途**: 实现 KCP 协议，提供基于 UDP 的可靠低延迟传输。
*   **理由**: 这是一个生产级的 KCP 实现，被广泛应用于 kcptun 等项目中，性能卓越。

### 2.2 WebSocket
*   **库名**: `github.com/gorilla/websocket`
*   **License**: ✅ BSD-2-Clause
*   **用途**: 在 HTTP 连接上建立全双工通信，用于穿透防火墙。
*   **理由**: Gorilla 是事实标准，稳定成熟；nhooyr.io 接口更现代（context-aware）。推荐 Gorilla 以保证兼容性。

### 2.3 SSH 隧道
*   **库名**: `golang.org/x/crypto/ssh`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 实现 SSH 客户端和服务端，建立加密隧道。
*   **理由**: 官方维护的加密库，安全可靠。

### 2.4 多路复用 (Multiplexing)
*   **库名**: `github.com/hashicorp/yamux`
*   **License**: ⚠️ MPL 2.0
*   **备选**: `github.com/xtaci/smux` (✅ MIT)
*   **用途**: 在单一 TCP 连接上复用多个逻辑流，用于内网穿透。
*   **理由**: Yamux 简单易用，文档齐全；Smux 针对性能优化（特别是配合 KCP）。优先推荐 Smux 以获得更宽松的 License 和更好的 KCP 适配性。

### 2.5 流量压缩 (Compression)
*   **库名**: `github.com/golang/snappy`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 对传输层流量进行 Snappy 压缩，减少带宽占用。
*   **理由**: 官方维护的 Go 实现，压缩速度快，CPU 占用低，非常适合实时网络流量。

## 3. 协议层 (Protocol Layer)
*   **库名**: `github.com/golang/snappy`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 对传输层数据进行压缩，减少带宽占用。
*   **理由**: Google 官方维护，压缩/解压速度极快，在平衡 CPU 占用和压缩率方面表现优异，非常适合实时网络传输。

## 3. 协议层 (Protocol Layer)

### 3.1 HTTP/HTTPS
*   **库名**: 标准库 `net/http` 配合 `github.com/elazarl/goproxy`
*   **License**: ✅ BSD-3-Clause (Go) / ✅ BSD-3-Clause (goproxy)
*   **用途**: 处理 HTTP 请求和 HTTPS CONNECT 隧道。
*   **理由**: 标准库足够强大，对于高性能需求可考虑 `github.com/valyala/fasthttp` (✅ MIT)，但标准库兼容性最好。

### 3.2 SOCKS5
*   **库名**: 自研或参考 `github.com/armon/go-socks5`
*   **License**: ✅ MIT
*   **用途**: SOCKS5 协议握手与转发。
*   **理由**: 协议逻辑不复杂，建议自研以支持更多定制功能（如 UDP Associate, 自定义认证）。

### 3.3 Shadowsocks (SS)
*   **库名**: `github.com/shadowsocks/go-shadowsocks2` (仅参考加密部分)
*   **License**: ✅ Apache 2.0
*   **用途**: 实现 SS 协议的加解密。
*   **理由**: 需要使用标准的 AEAD 加密算法（如 Chacha20-Poly1305, AES-GCM）。

## 4. 功能层 (Feature Layer)

### 4.1 流量控制 (Rate Limit)
*   **库名**: `golang.org/x/time/rate`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 基于令牌桶算法的限速。
*   **理由**: 官方扩展库，标准且高效。

### 4.2 DNS 解析
*   **库名**: `github.com/miekg/dns`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 构建 DNS 服务器和客户端，处理 DNS 报文。
*   **理由**: Go 语言中最权威的 DNS 库，CoreDNS 底层即使用此库。

### 4.3 缓存 (Cache)
*   **库名**: `github.com/patrickmn/go-cache`
*   **License**: ✅ MIT
*   **备选**: `github.com/hashicorp/golang-lru` (⚠️ MPL 2.0)
*   **用途**: DNS 缓存、认证信息缓存。
*   **理由**: go-cache 类似 Memcached 的内存版，简单易用，且 License 更宽松。

### 4.4 唯一 ID 生成
*   **库名**: `github.com/google/uuid`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 为每个连接生成唯一 Request ID，便于日志追踪。
*   **理由**: 标准 UUID 实现。

### 4.5 证书管理
*   **库名**: `golang.org/x/crypto/acme/autocert`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 自动从 Let's Encrypt 获取 HTTPS 证书。
*   **理由**: 官方库，方便实现 HTTPS 代理的自动化证书管理。

### 4.6 地理位置 (GeoIP)
*   **库名**: `github.com/oschwald/geoip2-golang`
*   **License**: ✅ ISC
*   **用途**: 基于 IP 地址判断地理位置，用于高级路由策略（如仅允许国内 IP 直连）。
*   **理由**: MaxMind 官方推荐的 Go 客户端，API 设计合理，性能良好。ISC 协议兼容性极佳。

## 5. 测试与辅助

### 5.1 单元测试
*   **库名**: `github.com/stretchr/testify`
*   **License**: ✅ MIT
*   **用途**: 断言和 Mock。
*   **理由**: 极大地简化了测试代码的编写。

### 5.2 性能分析
*   **库名**: 标准库 `net/http/pprof`
*   **License**: ✅ BSD-3-Clause
*   **用途**: 在线性能剖析。
