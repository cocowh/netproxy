# NetProxy 配置文档

本文档详细介绍 NetProxy 的配置方式和所有可用配置项。

## 目录

- [配置文件格式](#配置文件格式)
- [配置加载优先级](#配置加载优先级)
- [完整配置示例](#完整配置示例)
- [配置项详解](#配置项详解)
  - [监听器配置 (listeners)](#监听器配置-listeners)
  - [日志配置 (log)](#日志配置-log)
  - [认证配置 (auth)](#认证配置-auth)
  - [DNS 配置 (dns)](#dns-配置-dns)
  - [路由配置 (routing)](#路由配置-routing)
  - [隧道配置 (tunnel)](#隧道配置-tunnel)
  - [管理接口配置 (admin)](#管理接口配置-admin)
- [环境变量](#环境变量)
- [热更新](#热更新)

---

## 配置文件格式

NetProxy 支持以下配置文件格式：
- **YAML** (推荐)
- **JSON**
- **TOML**

默认配置文件路径为 `./config.yaml`，可通过 `--config` 参数指定其他路径。

```bash
netproxy --config /path/to/config.yaml
```

---

## 配置加载优先级

配置项的加载优先级从高到低为：

1. **命令行参数** - 最高优先级
2. **环境变量** - 前缀为 `NETPROXY_`
3. **配置文件** - YAML/JSON/TOML
4. **默认值** - 内置默认配置

---

## 完整配置示例

```yaml
# NetProxy 完整配置示例

# 监听器配置
listeners:
  # SOCKS5 代理
  - protocol: socks5
    transport: tcp
    addr: ":1080"
    announce: ""  # UDP Associate 公告地址
    rate_limit:
      enabled: false
      limit: 100    # 每秒请求数
      burst: 200    # 突发容量

  # HTTP/HTTPS 代理
  - protocol: http
    transport: tcp
    addr: ":8080"
    rate_limit:
      enabled: true
      limit: 50
      burst: 100

  # SPS 智能协议识别 (同时支持 SOCKS5 和 HTTP)
  - protocol: sps
    transport: tcp
    addr: ":3128"

  # TLS 加密监听
  - protocol: socks5
    transport: tls
    addr: ":1443"
    options:
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"

  # WebSocket 传输
  - protocol: http
    transport: ws
    addr: ":8088"
    options:
      path: "/proxy"

# 日志配置
log:
  level: "info"      # debug, info, warn, error
  path: ""           # 日志文件路径，空则输出到控制台

# 认证配置
auth:
  type: "local"      # local, http
  params:
    admin: "admin123"
    user1: "password1"
    user2: "password2"

# DNS 配置
dns:
  enabled: true
  addr: ":53"
  upstream: "8.8.8.8:53"
  rules:
    "google.com": "https://8.8.8.8/dns-query"
    "github.com": "1.1.1.1:53"

# 路由配置
routing:
  geoip: "/path/to/GeoLite2-Country.mmdb"
  remote_dns: "https://8.8.8.8/dns-query"
  upstreams:
    - "socks5://proxy1.example.com:1080"
    - "http://proxy2.example.com:8080"
  rules:
    - "direct: geoip:cn"
    - "proxy: domain:google.com"
    - "proxy: domain:youtube.com"
    - "direct: cidr:192.168.0.0/16"
    - "block: domain:ads.example.com"

# 隧道配置 (内网穿透)
tunnel:
  mode: ""           # bridge, client, 或空
  control_addr: ":7000"
  tunnels:
    ":8080": "web-server"
    ":3306": "db-server"
  server_addr: "bridge.example.com:7000"
  target_addr: "127.0.0.1:80"
  client_id: "my-client"
  token: "secret-token"
  tls:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
    ca_file: "/path/to/ca.pem"
    server_name: "bridge.example.com"
    skip_verify: false

# 管理接口配置
admin:
  addr: ":9090"
  token: "admin-secret"
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
```

---

## 配置项详解

### 监听器配置 (listeners)

监听器定义了 NetProxy 接受连接的端口和协议。

| 字段 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| `protocol` | string | 是 | - | 代理协议：`socks5`, `http`, `sps`, `mixed` |
| `transport` | string | 否 | `tcp` | 传输协议：`tcp`, `tls`, `ws`, `kcp` |
| `addr` | string | 是 | - | 监听地址，格式：`:port` 或 `ip:port` |
| `announce` | string | 否 | - | UDP Associate 公告地址（SOCKS5 专用） |
| `rate_limit` | object | 否 | - | 速率限制配置 |
| `options` | object | 否 | - | 传输层特定选项 |

#### 支持的协议 (protocol)

| 协议 | 说明 |
|------|------|
| `socks5` | SOCKS5 代理，支持 TCP CONNECT 和 UDP ASSOCIATE |
| `http` | HTTP/HTTPS 代理，支持 CONNECT 隧道 |
| `sps` | 智能协议识别，自动识别 SOCKS5/HTTP |
| `mixed` | 同 `sps`，混合模式 |

#### 支持的传输协议 (transport)

| 传输 | 说明 | 特定选项 |
|------|------|----------|
| `tcp` | 标准 TCP | - |
| `tls` | TLS 加密 TCP | `cert_file`, `key_file`, `ca_file` |
| `ws` | WebSocket | `path` |
| `kcp` | KCP 协议 | `sndwnd`, `rcvwnd`, `mtu` |

#### 速率限制配置 (rate_limit)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 是否启用速率限制 |
| `limit` | int | - | 每秒允许的请求数 |
| `burst` | int | - | 突发容量（令牌桶大小） |

#### TLS 选项 (options)

```yaml
options:
  cert_file: "/path/to/server.crt"   # 服务器证书
  key_file: "/path/to/server.key"    # 服务器私钥
  ca_file: "/path/to/ca.crt"         # CA 证书（用于客户端验证）
```

#### WebSocket 选项 (options)

```yaml
options:
  path: "/proxy"                      # WebSocket 路径
```

---

### 日志配置 (log)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `level` | string | `info` | 日志级别：`debug`, `info`, `warn`, `error` |
| `path` | string | `""` | 日志文件路径，空则输出到控制台 |

```yaml
log:
  level: "debug"
  path: "/var/log/netproxy/netproxy.log"
```

---

### 认证配置 (auth)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `type` | string | - | 认证类型：`local`, `http` |
| `params` | map | - | 认证参数 |

#### 本地认证 (local)

直接在配置文件中定义用户名和密码：

```yaml
auth:
  type: "local"
  params:
    username1: "password1"
    username2: "password2"
```

#### HTTP API 认证 (http)

通过远程 HTTP API 进行认证：

```yaml
auth:
  type: "http"
  params:
    url: "https://auth.example.com/verify"
```

API 请求格式：
```json
POST /verify
Content-Type: application/json

{
  "user": "username",
  "password": "password"
}
```

API 响应：
- `200 OK` - 认证成功
- 其他状态码 - 认证失败

---

### DNS 配置 (dns)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 是否启用 DNS 服务 |
| `addr` | string | `:53` | DNS 服务监听地址 |
| `upstream` | string | - | 默认上游 DNS 服务器 |
| `rules` | map | - | 域名到上游 DNS 的映射规则 |

```yaml
dns:
  enabled: true
  addr: ":5353"
  upstream: "8.8.8.8:53"
  rules:
    # 域名 -> 上游 DNS
    "google.com": "https://8.8.8.8/dns-query"    # DoH
    "github.com": "1.1.1.1:53"                    # UDP
    "internal.corp": "10.0.0.1:53"               # 内网 DNS
```

#### 支持的上游 DNS 格式

| 格式 | 示例 | 说明 |
|------|------|------|
| UDP | `8.8.8.8:53` | 标准 DNS over UDP |
| DoH | `https://8.8.8.8/dns-query` | DNS over HTTPS |

---

### 路由配置 (routing)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `geoip` | string | - | GeoIP 数据库路径 (MaxMind GeoLite2) |
| `remote_dns` | string | - | 代理域名使用的远程 DNS |
| `upstreams` | []string | - | 上游代理服务器列表 |
| `rules` | []string | - | 路由规则列表 |

```yaml
routing:
  geoip: "/path/to/GeoLite2-Country.mmdb"
  remote_dns: "https://8.8.8.8/dns-query"
  upstreams:
    - "socks5://user:pass@proxy1.example.com:1080"
    - "http://proxy2.example.com:8080"
  rules:
    - "direct: geoip:cn"
    - "proxy: domain:google.com"
    - "block: domain:ads.example.com"
```

#### 上游代理格式 (upstreams)

| 格式 | 示例 |
|------|------|
| SOCKS5 | `socks5://host:port` |
| SOCKS5 带认证 | `socks5://user:pass@host:port` |
| HTTP | `http://host:port` |
| HTTP 带认证 | `http://user:pass@host:port` |

#### 路由规则格式 (rules)

规则格式：`action: matcher`

**动作 (action)**：
| 动作 | 说明 |
|------|------|
| `direct` | 直接连接，不经过代理 |
| `proxy` | 通过上游代理连接 |
| `block` | 阻止连接 |

**匹配器 (matcher)**：
| 匹配器 | 格式 | 示例 |
|--------|------|------|
| 域名 | `domain:域名` | `domain:google.com` |
| GeoIP | `geoip:国家代码` | `geoip:cn` |
| CIDR | `cidr:IP段` | `cidr:192.168.0.0/16` |

**规则示例**：
```yaml
rules:
  # 中国 IP 直连
  - "direct: geoip:cn"
  
  # 私有网络直连
  - "direct: cidr:10.0.0.0/8"
  - "direct: cidr:172.16.0.0/12"
  - "direct: cidr:192.168.0.0/16"
  
  # 特定域名走代理
  - "proxy: domain:google.com"
  - "proxy: domain:youtube.com"
  - "proxy: domain:twitter.com"
  
  # 屏蔽广告域名
  - "block: domain:ads.example.com"
```

---

### 隧道配置 (tunnel)

内网穿透功能配置，支持 Bridge（服务端）和 Client（客户端）两种模式。

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `mode` | string | - | 模式：`bridge`, `client`, 或空 |
| `control_addr` | string | - | Bridge 控制端口地址 |
| `tunnels` | map | - | 端口到客户端 ID 的映射 |
| `server_addr` | string | - | Client 连接的 Bridge 地址 |
| `target_addr` | string | - | Client 转发的本地目标地址 |
| `client_id` | string | - | Client 标识 ID |
| `token` | string | - | 认证令牌 |
| `tls` | object | - | TLS 加密配置 |

#### Bridge 模式配置

Bridge 运行在公网服务器上，接受 Client 连接并转发流量。

```yaml
tunnel:
  mode: "bridge"
  control_addr: ":7000"           # 控制连接端口
  token: "secret-token"           # 认证令牌
  tunnels:
    ":8080": "web-server"         # 公网端口 -> 客户端 ID
    ":3306": "db-server"
    ":22": "ssh-server"
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    ca_file: "/path/to/ca.crt"    # 可选，用于验证客户端证书
```

#### Client 模式配置

Client 运行在内网，连接 Bridge 并将流量转发到本地服务。

```yaml
tunnel:
  mode: "client"
  server_addr: "bridge.example.com:7000"  # Bridge 地址
  target_addr: "127.0.0.1:80"             # 本地服务地址
  client_id: "web-server"                  # 客户端 ID
  token: "secret-token"                    # 认证令牌
  tls:
    enabled: true
    ca_file: "/path/to/ca.crt"            # CA 证书
    server_name: "bridge.example.com"      # SNI
    skip_verify: false                     # 是否跳过证书验证
```

#### TLS 配置 (tls)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `false` | 是否启用 TLS |
| `cert_file` | string | - | 证书文件路径 |
| `key_file` | string | - | 私钥文件路径 |
| `ca_file` | string | - | CA 证书路径 |
| `server_name` | string | - | 服务器名称 (SNI) |
| `skip_verify` | bool | `false` | 是否跳过证书验证 |

---

### 管理接口配置 (admin)

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `addr` | string | `:9090` | 管理接口监听地址 |
| `token` | string | - | 访问令牌（空则无需认证） |
| `tls` | object | - | TLS 配置 |

```yaml
admin:
  addr: ":9090"
  token: "admin-secret-token"
  tls:
    enabled: true
    cert_file: "/path/to/admin.crt"
    key_file: "/path/to/admin.key"
```

#### 管理接口 API

| 端点 | 方法 | 认证 | 说明 |
|------|------|------|------|
| `/health` | GET | 否 | 健康检查 |
| `/stats` | GET | 是 | 获取统计信息 |
| `/conns` | GET | 是 | 获取活跃连接 |
| `/metrics` | GET | 否 | Prometheus 格式指标 |
| `/stats/users` | GET | 是 | 用户统计信息 |
| `/stats/proxies` | GET | 是 | 代理统计信息 |

**认证方式**：在请求头中添加 `X-Admin-Token: your-token`

**示例**：
```bash
# 健康检查
curl http://localhost:9090/health

# 获取统计信息
curl -H "X-Admin-Token: admin-secret-token" http://localhost:9090/stats

# Prometheus 指标
curl http://localhost:9090/metrics
```

---

## 环境变量

所有配置项都可以通过环境变量覆盖，环境变量前缀为 `NETPROXY_`，使用下划线分隔层级。

| 配置项 | 环境变量 |
|--------|----------|
| `log.level` | `NETPROXY_LOG_LEVEL` |
| `log.path` | `NETPROXY_LOG_PATH` |
| `admin.addr` | `NETPROXY_ADMIN_ADDR` |
| `admin.token` | `NETPROXY_ADMIN_TOKEN` |
| `dns.enabled` | `NETPROXY_DNS_ENABLED` |
| `dns.addr` | `NETPROXY_DNS_ADDR` |
| `dns.upstream` | `NETPROXY_DNS_UPSTREAM` |

**示例**：
```bash
export NETPROXY_LOG_LEVEL=debug
export NETPROXY_ADMIN_TOKEN=my-secret-token
netproxy --config config.yaml
```

---

## 热更新

NetProxy 支持配置文件热更新。当配置文件发生变化时，以下配置项会自动重新加载：

- **路由规则** (`routing.rules`)

**注意**：以下配置项变更需要重启服务：
- 监听器配置 (`listeners`)
- 隧道配置 (`tunnel`)
- 认证配置 (`auth`)

---

## 最小配置示例

### 简单 SOCKS5 代理

```yaml
listeners:
  - protocol: socks5
    addr: ":1080"
```

### 简单 HTTP 代理

```yaml
listeners:
  - protocol: http
    addr: ":8080"
```

### 带认证的代理

```yaml
listeners:
  - protocol: sps
    addr: ":3128"

auth:
  type: local
  params:
    admin: "password123"
```

### 带路由规则的代理

```yaml
listeners:
  - protocol: socks5
    addr: ":1080"

routing:
  upstreams:
    - "socks5://proxy.example.com:1080"
  rules:
    - "direct: geoip:cn"
    - "proxy: domain:google.com"
```

---

## 常见问题

### Q: 如何同时支持 SOCKS5 和 HTTP？

使用 `sps` 或 `mixed` 协议：

```yaml
listeners:
  - protocol: sps
    addr: ":3128"
```

### Q: 如何启用 TLS 加密？

```yaml
listeners:
  - protocol: socks5
    transport: tls
    addr: ":1443"
    options:
      cert_file: "/path/to/cert.pem"
      key_file: "/path/to/key.pem"
```

### Q: 如何配置内网穿透？

**公网服务器 (Bridge)**：
```yaml
tunnel:
  mode: bridge
  control_addr: ":7000"
  tunnels:
    ":8080": "my-web"
  token: "secret"
```

**内网客户端 (Client)**：
```yaml
tunnel:
  mode: client
  server_addr: "公网IP:7000"
  target_addr: "127.0.0.1:80"
  client_id: "my-web"
  token: "secret"
```

### Q: 如何查看运行状态？

访问管理接口：
```bash
curl http://localhost:9090/stats
curl http://localhost:9090/metrics
```
