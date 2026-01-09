# 核心层 (Core Layer) 模块文档

## 1. ConfigManager (配置管理)

### 功能描述
负责应用程序配置的加载、解析、验证和热更新。支持从命令行参数 (Flags)、配置文件 (JSON/TOML/YAML) 和环境变量中读取配置。

### 接口设计

```go
package config

// Config 定义了全局配置结构
type Config struct {
    Server  ServerConfig  `mapstructure:"server"`
    Log     LogConfig     `mapstructure:"log"`
    Auth    AuthConfig    `mapstructure:"auth"`
    Modules ModuleConfig  `mapstructure:"modules"`
}

// Manager 接口定义
type Manager interface {
    // Load 加载配置，priority: flags > env > file
    Load() error
    
    // GetConfig 获取当前配置快照
    GetConfig() *Config
    
    // Watch 监听配置变化
    Watch(onChange func(newConfig *Config))
    
    // Save 持久化当前配置到文件
    Save() error
}
```

### 主要逻辑
1.  **初始化**: 绑定命令行参数，设置配置文件路径默认值。
2.  **加载顺序**:
    *   读取配置文件。
    *   读取环境变量 (前缀 `NETPROXY_`)。
    *   读取命令行参数。
    *   合并配置，优先级：命令行 > 环境变量 > 配置文件 > 默认值。
3.  **热更新**: 使用 `fsnotify` 监听配置文件变化，触发回调函数重新加载部分或全部配置。
4.  **验证**: 使用 struct tags 或自定义 Validator 验证配置项的合法性 (e.g., 端口范围, IP 格式)。

## 2. Logger (日志系统)

### 功能描述
提供统一的、高性能的结构化日志记录服务。支持多种输出目标 (Stdout, File)、日志轮转 (Rotation)、日志级别动态调整。

### 接口设计

```go
package logger

// Level 日志级别
type Level int

const (
    DebugLevel Level = iota
    InfoLevel
    WarnLevel
    ErrorLevel
    FatalLevel
)

// Logger 接口定义
type Logger interface {
    Debug(msg string, fields ...Field)
    Info(msg string, fields ...Field)
    Warn(msg string, fields ...Field)
    Error(msg string, fields ...Field)
    Fatal(msg string, fields ...Field)
    
    // With 创建带有上下文的新 Logger 实例
    With(fields ...Field) Logger
    
    // SetLevel 动态调整日志级别
    SetLevel(level Level)
}

// Field 结构化字段
type Field struct {
    Key   string
    Value interface{}
}
```

### 主要逻辑
1.  **后端封装**: 封装 `zap` 或 `zerolog`。
2.  **配置集成**: 从 `ConfigManager` 获取日志路径、级别、格式 (JSON/Console) 等配置。
3.  **上下文注入**: 在请求处理链中，将 RequestID、ClientIP 等信息注入 Logger，贯穿整个调用链。
4.  **轮转**: 集成 `lumberjack` 实现按大小或日期轮转日志文件。

## 3. LifecycleManager (生命周期管理)

### 功能描述
管理应用程序的启动、运行和停止过程。处理系统信号 (SIGINT, SIGTERM)，确保资源（数据库连接、文件句柄、网络监听器）能够优雅关闭 (Graceful Shutdown)。

### 接口设计

```go
package lifecycle

// Lifecycle 管理应用生命周期
type Lifecycle interface {
    // Start 启动所有注册的 Hook
    Start(ctx context.Context) error
    
    // Stop 停止所有注册的 Hook
    Stop(ctx context.Context) error
    
    // Append 注册生命周期钩子
    Append(hook Hook)
}

// Hook 定义启动和停止的逻辑
type Hook struct {
    OnStart func(context.Context) error
    OnStop  func(context.Context) error
}
```

### 主要逻辑
1.  **钩子注册**: 各个模块 (Service, Database, etc.) 在初始化时向 LifecycleManager 注册自己的 Start/Stop 逻辑。
2.  **启动流程**: 按注册顺序（或依赖顺序）依次执行 `OnStart`。如果有任一失败，触发回滚（执行已启动模块的 `OnStop`）。
3.  **信号监听**: 启动 goroutine 监听系统信号。
4.  **优雅关闭**:
    *   接收到退出信号。
    *   设置超时 Context。
    *   按反序执行 `OnStop`。
    *   强制关闭：如果超时未完成，强制退出。

## 4. EventManager (事件总线)

### 功能描述
提供进程内的发布/订阅 (Pub/Sub) 机制，用于模块间的解耦通信。例如：当检测到新的服务节点时，通知负载均衡器更新列表。

### 接口设计

```go
package event

// Event 事件结构
type Event struct {
    Topic   string
    Payload interface{}
    Time    time.Time
}

// Bus 接口定义
type Bus interface {
    // Publish 发布事件
    Publish(topic string, payload interface{})
    
    // Subscribe 订阅事件
    Subscribe(topic string, handler func(e Event))
    
    // Unsubscribe 取消订阅
    Unsubscribe(topic string, handler func(e Event))
}
```

### 主要逻辑
1.  **Topic 管理**: 使用 Map 维护 Topic 到 Subscriber List 的映射。
2.  **异步分发**: `Publish` 可以是同步阻塞的，也可以放入 Channel 异步处理，避免阻塞发布者。
3.  **错误处理**: Subscriber 的执行 panic 不应影响 EventManager 或其他 Subscriber。
