# 功能层 (Feature Layer) 模块文档

## 1. AuthModule (认证模块)

### 功能描述
提供统一的认证接口，支持多种认证后端（本地配置、文件、远程 API）。

### 接口设计

```go
package auth

// Authenticator 认证接口
type Authenticator interface {
    // Authenticate 验证用户名和密码
    // 返回 user info 和 error
    Authenticate(ctx context.Context, user, password string) (User, error)
}

// User 用户信息
type User struct {
    Username string
    Groups   []string
    Meta     map[string]interface{}
}
```

### 主要逻辑
1.  **Local Auth**: 读取 `users` 配置文件或内存 Map，比对 Hash 后的密码。
2.  **File Auth**: 类似 htpasswd，从文件加载用户名密码。
3.  **HTTP API Auth**: 发送 POST 请求到外部服务，验证凭据。支持缓存结果 (Cache) 以减少外部调用。
4.  **IP Auth**: 某些场景下基于源 IP 进行免密或特定权限认证。

## 2. ACLModule (访问控制)

### 功能描述
控制谁可以访问什么。基于 IP、域名、端口进行黑白名单过滤。

### 接口设计

```go
package acl

type Action int

const (
    Allow Action = iota
    Block
    Proxy // 强制走代理
    Direct // 强制直连
)

type RuleEngine interface {
    // Decide 根据请求元数据决定动作
    Decide(ctx context.Context, metadata Metadata) Action
}

type Metadata struct {
    ClientIP   net.IP
    TargetHost string
    TargetPort int
    Protocol   string
    User       string // From AuthModule
}
```

### 主要逻辑
1.  **IP Matching**: 使用 CIDR Trie 树 (e.g., `192.168.0.0/16`) 快速匹配 ClientIP 或 Resolved TargetIP。
2.  **Domain Matching**: 使用后缀树或 Map 匹配域名 (e.g., `*.google.com`).
3.  **GeoIP**: 集成 GeoIP 数据库，支持按国家/地区规则 (e.g., `GeoIP:CN` -> Direct).
4.  **External Source**: 支持从 URL 自动更新规则集（如 GFWList, AdBlock List）。

## 3. Router (路由模块)

### 功能描述
决定流量的下一跳。是核心的决策中心，结合 ACL 和 LoadBalancer 工作。

### 主要逻辑
1.  **Rule Evaluation**: 调用 ACLModule 获取 Action。
2.  **Routing**:
    *   **Direct**: 直接连接目标。
    *   **Block**: 关闭连接。
    *   **Proxy**: 选择一个上级代理 (Parent) 并转发。
3.  **Chain**: 支持定义多级代理链 (A -> B -> C -> Target)。
4.  **Failover**: 如果首选路径失败，尝试备用路径。

## 4. LoadBalancer (负载均衡)

### 功能描述
当有多个上级代理可用时，选择最优节点。

### 接口设计

```go
package loadbalancer

type Balancer interface {
    // Next 选择下一个 Peer
    Next(ctx context.Context, peers []*Peer) *Peer
}
```

### 主要逻辑
1.  **Round Robin**: 轮询。
2.  **Random**: 随机。
3.  **Least Conn**: 最小连接数。
4.  **Hash**: 基于源 IP 或目标 Host 的 Hash，保证同一用户/目标走同一线路。
5.  **Latency Based**: 定期 Ping 或 TCP Connect 探测，优先选择低延迟节点。

## 5. RateLimiter (流控)

### 功能描述
限制网络资源的使用，防止滥用。

### 接口设计

```go
package ratelimit

type Limiter interface {
    // Allow 是否允许当前的请求 (连接数检查)
    Allow(key string) bool
    
    // Wait 等待令牌 (带宽限制)
    Wait(ctx context.Context, key string, n int) error
}
```

### 主要逻辑
1.  **Connection Limit**: 维护 `Map[Key]int64` 计数器，Key 可以是 IP、用户或全局。连接建立 +1，断开 -1。
2.  **Bandwidth Limit**: 使用 `golang.org/x/time/rate`。
    *   **Global**: 全局总限速。
    *   **Per IP/User**: 动态创建 Limiter 实例，使用 LRU Cache 管理活跃用户的 Limiter。
    *   **Wrapper**: 实现 `net.Conn` 包装器，在 `Read/Write` 时调用 `Limiter.Wait`。

## 6. DNSModule (DNS 服务)

### 功能描述
提供 DNS 解析、缓存和转发服务。

### 主要逻辑
1.  **Server**: 监听 UDP/TCP :53。
2.  **Resolver**:
    *   **Local**: 读取 `/etc/hosts` 或自定义 Hosts 配置。
    *   **Upstream**: 转发给上游 DNS (8.8.8.8)。支持 UDP, TCP, DoH (DNS over HTTPS), DoT.
3.  **Cache**: 内存缓存 DNS 响应，遵守 TTL。
4.  **Poisoning Prevention**: 在非受信网络下，支持通过代理查询 DNS 以防污染。

## 7. StatsModule (统计与监控)

### 功能描述
收集运行时指标，提供监控 API。

### 主要逻辑
1.  **Metrics**:
    *   **Traffic**: 上行/下行流量 (Global, Per User, Per Proxy)。
    *   **Connections**: 当前并发数，总连接数。
    *   **Errors**: 错误率，失败计数。
2.  **Reporter**:
    *   **Log**: 定期打印到日志。
    *   **API**: 提供 `/metrics` 接口 (Prometheus 格式) 或 JSON API。
    *   **Push**: 主动推送到监控中心。
