# NetProxy 功能完善与架构增强计划 (Step 11)

## 1. 现状回顾 (Status Review)

在 Step 10 中，我们修复了最紧迫的生产级缺陷（SPS UDP 支持、Admin 安全）。然而，正如 `realized_step10.md` 和后续分析所指出的，NetProxy 在**功能完整性**和**架构灵活性**上仍有重要拼图缺失。

为了使 NetProxy 真正具备现代代理软件的竞争力，我们需要在 v1.1 版本前解决以下核心缺口。

---

## 2. 缺陷与不足分析 (Gap Analysis)

### 2.1 核心功能缺陷 (Functional Gaps)

#### 2.1.1 链式代理缺乏传输层组合能力 (Transport Layer in Chain Proxy)
*   **问题**: 目前 `SmartDialer` 构建代理链时，节点间的连接底层被硬编码为 TCP。无法实现 "SOCKS5 over TLS" 或 "Shadowsocks over WebSocket" 等高级组合。
*   **影响**: 在高阻断网络环境下，流量特征明显，代理链路生存能力弱。
*   **目标**: 支持通过 URL 参数或配置指定底层传输方式，例如 `socks5://host:port?transport=tls`。

#### 2.1.2 内网穿透安全性薄弱 (Tunnel Security)
*   **问题**: Tunnel Bridge (服务端) 和 Client (客户端) 之间仅依靠明文的 `ClientID` 进行匹配。
*   **影响**: 缺乏认证机制，存在恶意接入或中间人攻击风险。
*   **目标**: 引入 `Token` 或 `Key` 认证机制，在建立 Tunnel 控制通道时进行握手验证。

#### 2.1.3 配置热重载缺失 (No Hot-Reload)
*   **问题**: 系统未实现对配置文件的运行时监听和重载。修改路由规则或黑白名单必须重启服务。
*   **影响**: 运维体验差，修改配置会导致活跃连接中断。
*   **目标**: 利用 `fsnotify` 监听配置文件变化，动态更新 `Router` 规则。

### 2.2 架构集成不足 (Architectural Deficiencies)

#### 2.2.1 DNS 分流集成不彻底 (DNS Split-Horizon Integration)
*   **问题**: 内置 DNS Server 模块独立运作，未利用核心 Router 的分流能力。
*   **影响**: 无法实现“国内域名 -> 国内 DNS，国外域名 -> 国外 DoH”的策略。
*   **目标**: 将 `Router` 注入 `DNSServer`，根据域名匹配结果选择不同的上游 DNS。

---

## 3. 实现计划 (Implementation Plan)

### 3.1 任务 1: 传输层 (Transport) 插件化增强
*   **目标**: 让 `ProxyDialer` 和 `SmartDialer` 支持 TLS 和 WebSocket 作为底层传输。
*   **实现**:
    *   新增 `internal/transport/tls_dialer.go`: 实现 `TLSDialer` 包装器。
    *   新增 `internal/transport/ws_dialer.go`: 实现 `WSDialer` 包装器。
    *   修改 `internal/transport/smart_dialer.go`: 在解析代理 URL 时，识别 `transport=tls` 或 `transport=ws` 参数，并应用相应的包装器。

### 3.2 任务 2: Tunnel 安全增强
*   **目标**: 为 Tunnel 增加认证机制。
*   **实现**:
    *   修改 `TunnelConfig`: 增加 `Token` 字段。
    *   修改 `Bridge`: 在接受 Client 连接后，读取并验证 Token。
    *   修改 `Client`: 在连接 Bridge 后，发送 Token 进行握手。

### 3.3 任务 3: 配置热重载 (Hot-Reload)
*   **目标**: 动态加载路由规则。
*   **实现**:
    *   修改 `ConfigManager`: 使用 `fsnotify` 监听文件变化。
    *   修改 `main.go`: 注册回调函数，当 Config 变更时，重新加载 `Router` 规则。

### 3.4 任务 4: DNS 分流 (Split-Horizon)
*   **目标**: 策略化 DNS 解析。
*   **实现**:
    *   修改 `DNSServer`: 增加 `Router` 依赖。
    *   修改 `ServeDNS`: 在转发前查询 `Router`。如果域名匹配到 "Proxy" 规则，使用远程 DoH (如 8.8.8.8)；如果匹配 "Direct" 或 "Block"，使用本地/ISP DNS。

---

## 4. 执行顺序

1.  **Transport Layer**: 增强网络基础能力。
2.  **Tunnel Security**: 补齐安全短板。
3.  **Hot-Reload**: 提升运维体验。
4.  **DNS Split-Horizon**: 完善网络策略。
