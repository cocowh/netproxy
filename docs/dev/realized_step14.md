# NetProxy 功能完善计划 (Step 14)

## 1. 概述

本文档基于代码审计结果，梳理项目剩余的核心功能缺陷，作为下一阶段实现的执行路径。

---

## 2. 待实现任务

### 任务 1：GeoIP 匹配逻辑修正 (Critical)

**现状问题**:  
`GeoIPMatcherAdapter.Match` (router.go:212-216) 使用 `metadata.ClientIP` 进行匹配，这是**来源 IP**，而非**目标 IP**。导致 "访问中国 IP 直连，访问国外 IP 走代理" 的分流策略完全无效。

**修改方案**:
1. 修改 `GeoIPMatcherAdapter.Match`，解析 `metadata.TargetHost` 获取目标 IP
2. 如果 `TargetHost` 是域名，按需进行 DNS 解析获取 IP
3. 使用解析后的 IP 进行 GeoIP 匹配

**涉及文件**:
- `internal/feature/router/router.go`

---

### 任务 2：负载均衡策略增强 (High)

**现状问题**:  
仅支持 RoundRobin 和 Random 两种策略，缺乏生产环境常用的 Hash 和 LeastConn 策略。

**修改方案**:
1. 实现 `HashBalancer`：根据 ClientIP 或 TargetHost 计算 Hash，保证会话一致性
2. 实现 `LeastConnBalancer`：维护节点连接数计数器，选择负载最低的节点

**涉及文件**:
- `internal/feature/loadbalancer/loadbalancer.go`

---

### 任务 3：Tunnel 传输层加密 (High)

**现状问题**:  
Tunnel 控制通道使用明文 TCP，Token 以明文传输，存在安全风险。

**修改方案**:
1. `TunnelConfig` 增加 TLS 配置字段
2. Bridge 使用 `tls.Listen` 监听
3. Client 使用 `tls.Dial` 连接

**涉及文件**:
- `internal/core/config/config.go`
- `internal/protocol/tunnel/bridge.go`
- `internal/protocol/tunnel/client.go`

---

### 任务 4：Shadowsocks UDP Relay (Medium)

**现状问题**:  
SS 协议仅实现 TCP 转发，缺少 UDP Relay 能力。

**修改方案**:
1. 新建 `internal/protocol/ss/udp.go`
2. 实现 SS UDP 包的加解密和转发
3. 让 `ssHandler` 实现 `PacketHandler` 接口

**涉及文件**:
- `internal/protocol/ss/udp.go` (新建)
- `internal/protocol/ss/handler.go`

---

### 任务 5：Admin API HTTPS 支持 (Medium)

**现状问题**:  
Admin Server 仅支持 HTTP，生产环境需要 HTTPS。

**修改方案**:
1. `AdminConfig` 增加 TLS 配置字段
2. 支持 `http.ListenAndServeTLS`

**涉及文件**:
- `internal/core/config/config.go`
- `internal/core/admin/server.go`

---

## 3. 执行顺序

| 优先级 | 任务 | 预估工时 |
|--------|------|----------|
| P0 | 任务 1: GeoIP 匹配修正 | 2h |
| P1 | 任务 2: 负载均衡增强 | 4h |
| P1 | 任务 3: Tunnel TLS | 4h |
| P2 | 任务 4: SS UDP Relay | 6h |
| P2 | 任务 5: Admin HTTPS | 2h |

---

## 4. 验收标准

1. **GeoIP**: 配置 `geoip:cn -> direct` 后，访问国内 IP 直连，访问国外 IP 走代理
2. **负载均衡**: 配置多个上游代理后，Hash 策略保证同一客户端始终走同一节点
3. **Tunnel TLS**: 控制通道流量加密，Wireshark 抓包无法看到明文
4. **SS UDP**: 通过 SS 代理进行 DNS 查询成功
5. **Admin HTTPS**: 使用 `https://` 访问 Admin API 成功
