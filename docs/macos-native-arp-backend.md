# macOS 原生 ARP 扫描后端设计

## 目标

为 `crates/platform/src/network` 增加一个 macOS 专用的“原生 ARP 邻居快照”后端，替代当前主要依赖 `arp` / `ifconfig` / `route` 外部命令拼装结果的方式，同时保持现有扫描 UI、候选流式发现和证据补全链路不变。

本次设计聚焦的是后端边界，不是一次性把全部 macOS 网络发现都重写掉。

## 当前现状

当前 macOS 路径主要依赖以下命令：

- `arp -a -n`：读取邻居缓存
- `ifconfig -a`：读取接口和网段
- `route -n get default`：读取默认网关
- `dns-sd` / `dscacheutil`：补全主机名
- `ping`：主动刷新邻居表

这条链路能工作，但有几个明显问题：

- 输出格式是命令行文本，稳定性依赖系统版本和 locale。
- 邻居信息与接口信息来自多个命令，刷新时序不可控。
- 失败语义很粗，当前很难区分“没有数据”和“命令失败”。
- `crates/platform` 顶层是 `#![forbid(unsafe_code)]`，这意味着不能直接在现有 crate 里无成本接入 `libc` / Objective-C / SystemConfiguration FFI。

## 关键约束

原生 macOS 网络接口通常需要以下能力之一：

- 直接调用 BSD socket / routing socket / `sysctl` / `getifaddrs`
- 调用 SystemConfiguration / Network.framework / Foundation

这两条路在 Rust 里都基本会触发 `unsafe` FFI。由于 `crates/platform/src/lib.rs` 当前禁止 `unsafe`，直接把 FFI 写进现有 crate 不合适。

因此第一阶段的推荐方案不是“在这个 crate 里硬上 FFI”，而是：

1. 保持 Rust 平台层纯安全代码。
2. 增加一个 macOS 原生 helper 进程作为桥接层。
3. 由 helper 调用 Swift + SystemConfiguration / Foundation / BSD 接口拿到邻居快照。
4. 主程序通过稳定的文本协议消费 helper 输出。

这样做的好处：

- 隔离 `unsafe` 和 Apple 平台 API 复杂度。
- 主程序仍然保留现有跨平台抽象。
- helper 缺失或失败时，仍可回退到现有 `arp` 命令路径。

## 推荐架构

### 1. Rust 主程序中的后端选择

在 `neighbor_rows` 的 macOS 分支中引入如下优先级：

1. 原生 helper 后端
2. `arp -a -n`
3. `arp -an`

这保证：

- 新 helper 一旦可用，优先走原生路径。
- 当前版本不需要等待 helper 完成才可继续发布。

### 2. helper 职责边界

helper 只负责一件事：

- 返回一份本机 IPv4 邻居快照

它不负责：

- UI
- SSH 探测
- 设备分类
- DNS / SMB 二次补全

这样能把 helper 维持成一个窄接口组件。

### 3. helper 输出契约

当前 Rust 侧预留的契约为：

- 命令：`lanscanner-macos-arp-helper snapshot --contract neighbor-snapshot-v1`
- 输出：每行一条邻居记录
- 格式：`ip|mac|hostname|mdns_name`

要求：

- `ip` 必须是可解析 IPv4
- `mac` 必须能归一化成 6 字节 MAC
- `hostname` / `mdns_name` 允许为空
- `mdns_name` 若存在，优先保留 `.local` 结果

主程序只消费它需要的最小字段，避免 helper 协议过早复杂化。

## helper 建议实现

建议使用 Swift Command Line Tool，原因：

- 直接调用 Apple 平台 API 成本最低。
- 打包进 `.app` 资源目录或 helper 目录都比较自然。
- 调试和签名行为比 Rust + 手写 FFI 更可控。

建议采集链路：

1. `getifaddrs` 或 SystemConfiguration 获取启用中的 IPv4 接口
2. 通过路由邻居表 / ARP cache 获取 IPv4 -> MAC 映射
3. 若系统缓存里带 host name，则一并返回
4. 不做阻塞式 DNS 反查，避免把 snapshot 变成慢命令

## Rust 侧落地计划

### Phase 1

- 新增 `macos_backend` 模块
- 预留 helper 路径发现和文本协议解析
- macOS 邻居读取改为“helper 优先，`arp` 回退”
- 不改变上层扫描流程

### Phase 2

- 新增 Swift helper target
- 在 macOS 打包时把 helper 放进 app bundle
- 增加 helper 可观测日志和退出码约定

### Phase 3

- 把接口发现从 `ifconfig` 迁移到原生 helper 或独立原生接口模块
- 把默认网关获取从 `route` 迁移到原生 API
- 统一成 macOS 网络快照提供者，减少多命令拼接

## 错误处理原则

- helper 不存在：静默回退到 `arp`
- helper 启动失败：静默回退到 `arp`
- helper 输出不合法：丢弃非法行，保留合法行
- helper 完全空结果：继续尝试 `arp`

这样不会让“设计中的原生后端”破坏当前可用性。

## 本次代码变更对应关系

本次已经在 Rust 侧落下了第一阶段骨架：

- `crates/platform/src/network/macos_backend.rs`
  提供 helper 发现、协议常量、输出解析
- `crates/platform/src/network/neighbor_rows.rs`
  macOS 邻居读取顺序已调整为 helper 优先、命令回退

这意味着后续只需要补 helper 可执行文件，就能把原生后端接到现有扫描链路上，而不需要再改 UI 或扫描任务模型。
