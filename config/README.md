# Hiddify Core 配置模块

本目录包含 Hiddify Core 的配置处理相关代码，负责解析、构建和管理 Hiddify 的各种配置选项。

## 主要功能

### 配置解析与构建
- 支持多种格式配置文件的解析（JSON、YAML、Clash）
- 将用户配置转换为 sing-box 可用的标准格式
- 根据 HiddifyOptions 构建完整配置

### 配置组件
- **DNS 配置**：设置本地、远程 DNS 服务器及其策略
- **路由规则**：管理流量分流规则，支持按地区、域名等条件路由
- **入站/出站配置**：管理各种协议的入站和出站连接
- **日志配置**：控制日志级别和输出位置
- **Clash API**：提供与 Clash 兼容的 API 接口

### WARP 集成
- 支持 Cloudflare WARP 配置生成和管理
- 提供 WireGuard 配置转换为 sing-box 格式的功能

### 配置服务
- 提供 gRPC 服务接口，用于远程配置管理
- 支持配置验证和调试功能

## 核心组件

### HiddifyOptions
定义了 Hiddify 特有的配置选项，包括：
- 日志设置
- Clash API 设置
- 区域设置
- 广告拦截
- WARP 配置
- 多路复用设置
- 入站/出站选项

### 配置构建流程
1. 解析用户提供的配置文件（`ParseConfig`/`ParseConfigContent`）
2. 应用 HiddifyOptions 中的设置（`BuildConfig`）
3. 设置各个组件（DNS、路由、入站、出站等）
4. 生成最终的 JSON 配置（`BuildConfigJson`）

### 工具函数
- 配置验证（`validateResult`）
- 配置调试（`SaveCurrentConfig`）
- JSON 转换（`ToJson`）

## 使用示例

```go
// 解析配置文件
content, err := ParseConfig("/path/to/config.json", true)

// 使用默认 Hiddify 选项构建配置
options, err := ParseConfigContentToOptions(string(content), true, DefaultHiddifyOptions(), false)

// 生成最终配置
configJson, err := BuildConfigJson(*DefaultHiddifyOptions(), *options)
```

## 与其他模块的关系
- 被 `cmd` 包调用，提供命令行接口
- 被 `v2` 包调用，提供核心功能实现
- 被 `mobile` 包调用，提供移动平台接口