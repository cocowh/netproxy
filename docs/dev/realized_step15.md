# NetProxy 待实现功能清单 (Step 15)

## 1. 概述

本文档基于 `docs/dev/architecture.md` 设计文档和各模块设计文档，对比当前项目实现，梳理出尚未完成的功能点，作为后续开发的执行指导。

---

## 2. 待实现功能清单

### 2.1 负载均衡模块 (LoadBalancer)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **Weight (权重)** | P1 | 实现 `WeightedBalancer`，维护节点权重配置，按权重比例分配流量 |
| **Latency Based (延迟优先)** | P1 | 定期 TCP Connect 探测各节点延迟，优先选择低延迟节点 |
| **健康检查 (Health Check)** | P0 | 后台 goroutine 定期探测上游连通性，自动剔除不可用节点 |

**实现方案**:
```go
// internal/feature/loadbalancer/health.go
type HealthChecker struct {
    peers    []string
    healthy  sync.Map // map[string]bool
    interval time.Duration
    timeout  time.Duration
}

func (h *HealthChecker) Start(ctx context.Context) {
    ticker := time.NewTicker(h.interval)
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            for _, peer := range h.peers {
                go h.checkPeer(peer)
            }
        }
    }
}

func (h *HealthChecker) checkPeer(peer string) {
    conn, err := net.DialTimeout("tcp", peer, h.timeout)
    if err != nil {
        h.healthy.Store(peer, false)
        return
    }
    conn.Close()
    h.healthy.Store(peer, true)
}
```

---

### 2.2 内网穿透模块 (Tunnel)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **Server 组件** | P2 | 实现独立的 Server 端，连接 Bridge 的 Data Port，将用户流量转发给 Bridge |
| **P2P 打洞** | P2 | 实现 UDP Hole Punching，尝试让两端直连，失败则回退到 Relay 模式 |
| **UDP 穿透** | P2 | 在 Yamux 多路复用基础上封装 UDP 数据包 |

**实现方案**:
- Server 组件参考 Client 实现，反向连接 Bridge
- P2P 打洞需要 STUN 服务器协助获取公网地址

---

### 2.3 认证模块 (AuthModule)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **File Auth (htpasswd)** | P2 | 解析 Apache htpasswd 格式文件，支持 bcrypt/MD5/SHA 哈希 |
| **IP Auth** | P2 | 基于源 IP 进行免密认证，与 ACL 模块集成 |
| **认证结果缓存** | P1 | HTTP Auth 增加 LRU Cache，支持配置 TTL |

**实现方案**:
```go
// internal/feature/auth/cache.go
type CachedAuthenticator struct {
    backend Authenticator
    cache   *lru.Cache
    ttl     time.Duration
}

type cacheEntry struct {
    user      *User
    expiresAt time.Time
}

func (a *CachedAuthenticator) Authenticate(ctx context.Context, user, pass string) (*User, error) {
    key := user + ":" + pass
    if entry, ok := a.cache.Get(key); ok {
        if e := entry.(*cacheEntry); time.Now().Before(e.expiresAt) {
            return e.user, nil
        }
    }
    u, err := a.backend.Authenticate(ctx, user, pass)
    if err == nil {
        a.cache.Add(key, &cacheEntry{user: u, expiresAt: time.Now().Add(a.ttl)})
    }
    return u, err
}
```

---

### 2.4 访问控制模块 (ACLModule)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **端口黑白名单** | P2 | 在 Metadata 中增加 TargetPort 检查，支持端口范围 (e.g., 1-1024) |
| **正则域名匹配** | P2 | 增加 RegexMatcher，编译正则表达式进行匹配 |
| **外部规则源更新** | P2 | 定期从 URL 拉取规则文件 (GFWList, AdBlock)，解析后更新 Trie |

**实现方案**:
```go
// internal/feature/acl/port.go
type PortMatcher struct {
    ranges []PortRange // e.g., [{1, 1024}, {8080, 8080}]
}

func (m *PortMatcher) Match(port int) bool {
    for _, r := range m.ranges {
        if port >= r.Start && port <= r.End {
            return true
        }
    }
    return false
}
```

---

### 2.5 流控模块 (RateLimiter)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **连接数限制** | P1 | 实现 `ConnectionLimiter`，维护 `map[key]int64` 计数器 |
| **Per User 限速** | P1 | 与 Auth 模块集成，按用户名创建独立的 Limiter 实例 |
| **Per Port 限速** | P2 | 按监听端口维度创建 Limiter |
| **Conn Wrapper 限速** | P1 | 实现 `RateLimitedConn`，在 Read/Write 时调用 Limiter.Wait |

**实现方案**:
```go
// internal/feature/ratelimit/conn.go
type RateLimitedConn struct {
    net.Conn
    readLimiter  *rate.Limiter
    writeLimiter *rate.Limiter
}

func (c *RateLimitedConn) Read(b []byte) (int, error) {
    if err := c.readLimiter.WaitN(context.Background(), len(b)); err != nil {
        return 0, err
    }
    return c.Conn.Read(b)
}

func (c *RateLimitedConn) Write(b []byte) (int, error) {
    if err := c.writeLimiter.WaitN(context.Background(), len(b)); err != nil {
        return 0, err
    }
    return c.Conn.Write(b)
}

// internal/feature/ratelimit/connection.go
type ConnectionLimiter struct {
    mu       sync.Mutex
    counts   map[string]int64
    maxConns int64
}

func (l *ConnectionLimiter) Allow(key string) bool {
    l.mu.Lock()
    defer l.mu.Unlock()
    if l.counts[key] >= l.maxConns {
        return false
    }
    l.counts[key]++
    return true
}

func (l *ConnectionLimiter) Release(key string) {
    l.mu.Lock()
    defer l.mu.Unlock()
    if l.counts[key] > 0 {
        l.counts[key]--
    }
}
```

---

### 2.6 DNS 模块 (DNSModule)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **DoT (DNS over TLS)** | P2 | 实现 `DoTResolver`，使用 TLS 连接上游 DNS |
| **Hosts 文件支持** | P1 | 启动时读取 /etc/hosts 或自定义文件，优先本地解析 |
| **并发解析优化** | P2 | 同时查询多个上游，返回最快响应 |

**实现方案**:
```go
// internal/feature/dns/hosts.go
type HostsResolver struct {
    hosts map[string]net.IP // domain -> IP
}

func LoadHosts(path string) (*HostsResolver, error) {
    // 解析 hosts 文件格式: IP domain [alias...]
}

func (r *HostsResolver) Resolve(domain string) (net.IP, bool) {
    ip, ok := r.hosts[strings.TrimSuffix(domain, ".")]
    return ip, ok
}

// internal/feature/dns/dot.go
type DoTResolver struct {
    Address string // e.g., "8.8.8.8:853"
}

func (r *DoTResolver) Resolve(q *dns.Msg) (*dns.Msg, error) {
    conn, err := tls.Dial("tcp", r.Address, &tls.Config{})
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    // 发送 DNS 查询并读取响应
}
```

---

### 2.7 协议层 (Protocol Layer)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **反向代理 (Reverse Proxy)** | P2 | 解析 HTTP Host 头，根据配置分发到不同后端 |
| **MITM (中间人解密)** | P3 | 动态生成证书，解密 HTTPS 流量进行审计 |
| **透明代理 (Transparent)** | P2 | 读取 SO_ORIGINAL_DST 获取原始目标地址 |
| **SOCKS5 BIND** | P3 | 实现 SOCKS5 BIND 命令，支持 FTP 主动模式 |

**实现方案**:
```go
// internal/protocol/http/reverse.go
type ReverseProxyHandler struct {
    routes map[string]string // Host -> Backend
}

func (h *ReverseProxyHandler) Handle(ctx context.Context, conn net.Conn) error {
    // 1. 读取 HTTP 请求
    // 2. 解析 Host 头
    // 3. 查找后端地址
    // 4. 转发请求并返回响应
}

// internal/protocol/transparent/transparent_linux.go
func GetOriginalDst(conn *net.TCPConn) (net.Addr, error) {
    // 使用 syscall.GetsockoptIPv6Mreq 或 SO_ORIGINAL_DST
}
```

---

### 2.8 传输层 (Transport Layer)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **UDP over TLS** | P0 | 将 UDP 数据包封装为 TLS 流，添加长度前缀 |
| **UDP over WS** | P0 | 将 UDP 数据包封装为 WebSocket Binary Message |
| **自定义加密 (AES-256)** | P3 | 实现 `CryptoConn` 包装器，在 Read/Write 时加解密 |
| **流量压缩集成** | P2 | 将现有 Snappy 压缩集成到代理链路中 |

**实现方案**:
```go
// internal/transport/udp_over_tls.go
type UDPOverTLS struct {
    tlsConn net.Conn
}

func (u *UDPOverTLS) WriteTo(p []byte, addr net.Addr) (int, error) {
    // 封装: [2-byte length][payload]
    header := make([]byte, 2)
    binary.BigEndian.PutUint16(header, uint16(len(p)))
    u.tlsConn.Write(header)
    return u.tlsConn.Write(p)
}

func (u *UDPOverTLS) ReadFrom(p []byte) (int, net.Addr, error) {
    // 解封装
    header := make([]byte, 2)
    io.ReadFull(u.tlsConn, header)
    length := binary.BigEndian.Uint16(header)
    return io.ReadFull(u.tlsConn, p[:length])
}

// internal/transport/crypto.go
type CryptoConn struct {
    net.Conn
    cipher cipher.AEAD
}

func (c *CryptoConn) Read(b []byte) (int, error) {
    // 读取加密数据并解密
}

func (c *CryptoConn) Write(b []byte) (int, error) {
    // 加密数据并写入
}
```

---

### 2.9 统计与监控 (StatsModule)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **Per User 统计** | P0 | 与 Auth 模块集成，按用户名维度记录流量 |
| **Per Proxy 统计** | P1 | 按上游代理地址维度记录流量和连接数 |
| **Prometheus 格式** | P1 | 实现 /metrics 接口，输出标准 Prometheus 格式 |
| **流量上报 (Push)** | P2 | 定期将统计数据 POST 到监控中心 |

**实现方案**:
```go
// internal/feature/stats/prometheus.go
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
    snapshot := s.statsCollector.GetStats()
    fmt.Fprintf(w, "# HELP netproxy_connections_active Active connections\n")
    fmt.Fprintf(w, "# TYPE netproxy_connections_active gauge\n")
    fmt.Fprintf(w, "netproxy_connections_active %d\n", snapshot.ActiveConnections)
    fmt.Fprintf(w, "# HELP netproxy_traffic_bytes_total Total traffic bytes\n")
    fmt.Fprintf(w, "# TYPE netproxy_traffic_bytes_total counter\n")
    fmt.Fprintf(w, "netproxy_traffic_bytes_total{direction=\"ingress\"} %d\n", snapshot.IngressBytes)
    fmt.Fprintf(w, "netproxy_traffic_bytes_total{direction=\"egress\"} %d\n", snapshot.EgressBytes)
}

// internal/feature/stats/user.go
type UserStatsCollector struct {
    mu    sync.RWMutex
    users map[string]*UserStats
}

type UserStats struct {
    Ingress int64
    Egress  int64
    Conns   int64
}
```

---

### 2.10 服务层 (Service Layer)

| 功能 | 优先级 | 实现思路 |
|------|--------|----------|
| **端口范围监听** | P2 | 解析 `:8000-8010` 格式，循环创建多个 Listener |
| **端口复用 (SO_REUSEPORT)** | P3 | 使用 `golang.org/x/sys/unix` 设置 socket 选项 |
| **热更新监听配置** | P2 | 对比新旧配置，增量启动/关闭监听器 |

**实现方案**:
```go
// internal/service/listener/range.go
func ParsePortRange(addr string) ([]string, error) {
    // 解析 ":8000-8010" -> [":8000", ":8001", ..., ":8010"]
    host, portRange, err := net.SplitHostPort(addr)
    if err != nil {
        return nil, err
    }
    parts := strings.Split(portRange, "-")
    if len(parts) == 2 {
        start, _ := strconv.Atoi(parts[0])
        end, _ := strconv.Atoi(parts[1])
        var addrs []string
        for p := start; p <= end; p++ {
            addrs = append(addrs, net.JoinHostPort(host, strconv.Itoa(p)))
        }
        return addrs, nil
    }
    return []string{addr}, nil
}
```

---

## 3. 优先级排序

### P0 - 关键功能 (影响核心可用性)
1. **健康检查** - 上游代理故障时无法自动切换
2. **UDP over TLS/WS** - 安全传输模式下 UDP 不可用
3. **Per User 统计** - 无法追踪用户流量
4. **连接数限制** - 无法防止资源耗尽

### P1 - 重要功能 (影响生产环境部署)
1. **权重负载均衡** - 无法按节点性能分配流量
2. **延迟优先负载均衡** - 无法自动选择最优节点
3. **Prometheus 监控** - 无法接入标准监控系统
4. **Hosts 文件支持** - 本地域名解析不便
5. **认证结果缓存** - HTTP Auth 性能优化
6. **Conn Wrapper 限速** - 精细化带宽控制

### P2 - 增强功能 (提升用户体验)
1. **反向代理** - 无法作为 Web 服务器前端
2. **透明代理** - 无法实现网关级代理
3. **P2P 打洞** - 内网穿透效率低
4. **外部规则源** - 规则更新不便
5. **端口范围监听** - 批量端口配置繁琐
6. **DoT 支持** - DNS 加密传输
7. **流量压缩集成** - 降低带宽消耗

### P3 - 高级功能 (特定场景需求)
1. **MITM 解密** - 需要审计 HTTPS 流量时使用
2. **SOCKS5 BIND** - FTP 主动模式支持
3. **自定义加密** - 流量混淆需求
4. **端口复用** - 多进程部署场景

---

## 4. 建议下一步计划 (Step 16)

基于优先级分析，建议 Step 16 聚焦于 P0 级别任务：

### 任务 1: 负载均衡健康检查
**涉及文件**: `internal/feature/loadbalancer/health.go` (新建)
- 实现 `HealthChecker` 结构体
- 后台 goroutine 定期 TCP Connect 探测
- 自动剔除不可用节点，恢复后自动加入
- 支持配置探测间隔 (默认 10s) 和超时 (默认 3s)

### 任务 2: 连接数限制
**涉及文件**: `internal/feature/ratelimit/connection.go` (新建)
- 实现 `ConnectionLimiter` 结构体
- 支持全局、Per IP、Per User 维度
- 与 ServiceInstance 集成

### 任务 3: Per User 流量统计
**涉及文件**: `internal/feature/stats/user.go` (新建)
- 实现 `UserStatsCollector` 结构体
- 与 Auth 模块集成，获取用户名
- 按用户维度记录 Ingress/Egress/Conns

### 任务 4: UDP over TLS/WS
**涉及文件**: 
- `internal/transport/udp_over_tls.go` (新建)
- `internal/transport/udp_over_ws.go` (新建)
- 实现 `net.PacketConn` 接口
- 添加长度前缀封装 UDP 数据包

---

## 5. 总结

当前 NetProxy 项目核心代理能力（HTTP/SOCKS5/SS/Tunnel）已基本完备。待实现功能主要集中在：

1. **运维能力**: 健康检查、连接数限制、监控指标、用户流量统计
2. **高级路由**: 权重/延迟负载均衡、外部规则源
3. **协议扩展**: 反向代理、透明代理、MITM
4. **传输增强**: UDP over TLS/WS、自定义加密

建议按照 P0 -> P1 -> P2 -> P3 的优先级逐步完善。
