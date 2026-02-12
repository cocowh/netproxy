画# NetProxy 开发指导文档入口

## 描述

本文档为项目的具体实现指导文档入口，用于指导 AI 渐进式完善项目。

## 文档结构

```
docs/dev/
├── architecture.md          # 总体架构设计
├── design.md                # 初始设计需求
├── package.md               # 依赖库选型
├── modules/                 # 模块设计文档
│   ├── core_layer.md
│   ├── feature_layer.md
│   ├── protocol_layer.md
│   ├── service_layer.md
│   └── transport_layer.md
│
├── realized_template.md     # 🔑 开发指导文档模板（生成新 step 时参考）
├── realized_step1.md        # 本文档（入口）
├── realized_step2.md        # Step 2 实现指导
├── ...
└── realized_stepN.md        # Step N 实现指导
```

## 使用说明

### 执行开发任务时

1. 找到最新的未完成 step 文档（状态为 ⏳ 或 🚧）
2. 阅读文档中的背景和任务清单
3. 按顺序执行任务
4. 完成后更新任务清单状态
5. 将文档状态改为 ✅ 已完成

### 生成新的 step 文档时

1. 参考 `realized_template.md` 模板
2. 按模板结构填写内容
3. 确保包含完整的实现指导和代码示例

## 进度总览

### 基础功能 (Step 1-15) ✅ 已完成

| Step | 功能 | 状态 |
|------|------|------|
| Step 1 | 项目初始化与入口 | ✅ |
| Step 2 | 功能完善度分析 | ✅ |
| Step 3-5 | 核心架构实现 | ✅ |
| Step 6-10 | 协议层实现 (SOCKS5/HTTP/SS/Tunnel) | ✅ |
| Step 11-15 | 功能层完善 (路由/认证/统计/DNS) | ✅ |

### VPN 协议支持 (Step 16+) ⏳ 待开始

| Step | 功能 | 状态 | 优先级 |
|------|------|------|--------|
| Step 16 | Trojan 协议 | ⏳ 待开始 | P0 |
| Step 17 | VMess 协议 | ⏳ 待开始 | P0 |
| Step 18 | VLESS 协议 | ⏳ 待开始 | P0 |
| Step 19 | Hysteria2 协议 | ⏳ 待开始 | P1 |

### 传输层增强 (待规划)

| Step | 功能 | 状态 | 优先级 |
|------|------|------|--------|
| - | QUIC 传输 | ⏳ 待规划 | P1 |
| - | uTLS 指纹伪装 | ⏳ 待规划 | P1 |
| - | gRPC 传输 | ⏳ 待规划 | P2 |

### 管理能力增强 (待规划)

| Step | 功能 | 状态 | 优先级 |
|------|------|------|--------|
| - | 订阅链接生成 | ⏳ 待规划 | P1 |
| - | 用户流量管理 | ⏳ 待规划 | P1 |
| - | 集群模式 | ⏳ 待规划 | P2 |

## 背景

docs/design.md 是本项目的初始文档，根据本文档生成了 docs/architecture.md

根据 docs/architecture.md 生成了本项目的目录结构、依赖文档 docs/package.md、docs/modules下的各模块文档

## 原始需求

首要需求是根据背景中介绍的文档实现每个模块的具体代码，每个模块中的代码逻辑完善，完成后整体项目可直接编译。

在实现之前需要梳理文档是否合适，若有不妥先调整整体设计以及相关的模块、依赖等文档，然后反馈修改了什么，再由我确认是否需要继续实现首要需求。