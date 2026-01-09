# NetProxy 最终集成与交付计划 (Step 6)

## 1. 现状回顾 (Status Review)

基于 `Step 5` 的分析，NetProxy 项目的核心架构（五层模型）已完全落地，关键技术难点（智能路由、链式代理、内网穿透）均已攻克。项目完成度约为 90%。

当前剩余的主要工作不再是“从零开发”，而是将已有的功能模块（认证、流控、DNS）在启动入口 (`main.go`) 和核心服务 (`Instance`) 中进行最后的**组装与串联**。

## 2. 集成缺口分析 (Integration Gaps)

经过代码审查，发现以下功能模块虽然已实现，但尚未被主程序调用：

### 2.1 认证模块未挂载 (Authentication Detached)
*   **问题**: `internal/feature/auth` 已包含 `LocalAuthenticator`，但 `socks5.NewSOCKS5Handler` 和 `http.NewHTTPHandler` 在初始化时未接收任何认证配置。
*   **后果**: 无论配置文件如何设置，代理服务当前默认无认证，存在安全风险。
*   **需求**: 需要解析配置中的用户信息，注入到 Handler 中。

### 2.2 流控模块未启用 (RateLimiter Inactive)
*   **问题**: `internal/service/instance.go` 结构体中有 `limiter` 字段，但在 `NewServiceInstance` 工厂方法中没有初始化逻辑，`main.go` 也没传入相关参数。
*   **后果**: 限速和连接数限制功能失效。
*   **需求**: 在 Config 中增加流控配置，并在创建 Instance 时初始化 `TokenBucketLimiter`。

### 2.3 DNS 服务未启动 (DNS Server Missing)
*   **问题**: `internal/feature/dns` 模块是完整的，但 `cmd/netproxy/main.go` 中没有启动 DNS Server 的代码路径。
*   **后果**: 用户无法使用 NetProxy 作为 DNS 代理（DoH/UDP）。
*   **需求**: 在 Config 中增加 DNS Server 配置段，并在 `main.go` 生命周期中启动 DNS Server。

---

## 3. Step 6 执行计划 (Execution Plan)

为了实现 100% 的功能覆盖，需执行以下任务：

### 3.1 任务 1: 集成认证模块 (Integrate Authentication)

**目标**: 让 SOCKS5 和 HTTP 代理支持用户名/密码认证。

**修改点**:
1.  **Config**: 确保 `AuthConfig` 能被正确解析。
2.  **Main**: 在 `main.go` 中读取认证配置，创建 `LocalAuthenticator` 实例。
3.  **Handlers**:
    *   修改 `socks5.NewSOCKS5Handler` 签名，接受 `auth.Authenticator`。内部配置 `armon/go-socks5` 的 `Credentials` 回调。
    *   修改 `http.NewHTTPHandler` 签名，接受 `auth.Authenticator`。内部实现 `Proxy-Authorization` 头检查。

### 3.2 任务 2: 集成流控模块 (Integrate Rate Limiting)

**目标**: 支持全局或单实例的连接速率限制。

**修改点**:
1.  **Config**: 在 `ListenerConfig` 或全局配置中增加 `RateLimit` 字段 (limit, burst)。
2.  **Main**: 根据配置创建 `ratelimit.TokenBucketLimiter`。
3.  **Instance**: 在 `NewServiceInstance` 时传入 Limiter 实例。

### 3.3 任务 3: 启动 DNS 服务 (Activate DNS Server)

**目标**: 启用独立的 DNS 代理端口。

**修改点**:
1.  **Config**: 增加 `DNSConfig` 结构体：
    ```go
    type DNSConfig struct {
        Enabled    bool   `mapstructure:"enabled"`
        Addr       string `mapstructure:"addr"`       // e.g. :53
        Upstream   string `mapstructure:"upstream"`   // e.g. 8.8.8.8:53 or https://1.1.1.1/dns-query
    }
    ```
2.  **Main**:
    *   读取 DNS 配置。
    *   如果启用，初始化 `dns.NewServer`。
    *   将 DNS Server 的 `Start`/`Stop` 注册到 `Lifecycle` 钩子中。

## 4. 预期结果

完成上述步骤后，NetProxy 将填补最后的功能拼图，完全满足 `architecture.md` 中描述的所有特性，成为一个功能完备的生产级代理服务器。
