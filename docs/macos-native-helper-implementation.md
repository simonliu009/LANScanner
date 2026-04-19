# macOS Native Helper Implementation Plan

## 目标

在不破坏 `crates/platform` 的 `unsafe` 禁令前提下，为 LANScanner 提供一个可打包、可替换、可独立调试的 macOS 原生网络 helper。

## 为什么需要 helper

当前 Rust 平台层是安全代码优先，而 macOS 原生网络能力通常依赖：

- `getifaddrs`
- `sysctl`
- `SystemConfiguration`
- `IOKit`

这些接口在 Rust 里会迅速走向 FFI 和 `unsafe`。使用 Swift helper 可以把平台复杂度隔离出去。

## Rust 与 helper 的边界

Rust 主程序负责：

- 调用 helper
- 解析输出
- 合并为 `NetworkInterface` / `NeighborEvidence`
- 处理回退逻辑

helper 负责：

- 提供稳定快照
- 屏蔽 Apple 平台 API 差异

## 第一阶段功能

### interfaces snapshot

输入：

```text
interfaces --contract interface-snapshot-v1
```

输出字段：

- `id`
- `name`
- `ipv4`
- `prefix`
- `mac`
- `type`
- `is_primary`

### neighbors snapshot

输入：

```text
neighbors --contract neighbor-snapshot-v1
```

输出字段：

- `ip`
- `mac`
- `hostname`
- `mdns_name`

## Swift 端建议拆分

- `InterfaceSnapshotProvider`
  负责 `getifaddrs`、接口名、IPv4、prefix、MAC、primary 推断
- `NeighborSnapshotProvider`
  负责 IPv4 ARP / 邻居表读取
- `LineProtocolEncoder`
  负责输出转义和逐行编码
- `CommandRouter`
  负责命令分发和错误码

当前仓库中的 helper 骨架已经按这个拆分落地：

- `tools/macos-arp-helper/Sources/Models.swift`
- `tools/macos-arp-helper/Sources/LineProtocol.swift`
- `tools/macos-arp-helper/Sources/InterfaceSnapshotProvider.swift`
- `tools/macos-arp-helper/Sources/NeighborSnapshotProvider.swift`
- `tools/macos-arp-helper/Sources/CommandRouter.swift`
- `tools/macos-arp-helper/Sources/main.swift`

## Rust 端后续改造点

- `neighbor_rows.rs`
  已经支持 helper 优先的 macOS 邻居读取
- `network/mod.rs`
  下一步要把接口发现也切到 helper 优先
- `macos_backend.rs`
  后续增加 interface 快照解析和 helper 健康检查

## 第二阶段功能

- 默认网关原生读取
- mDNS 主动补全
- NetBIOS / SMB 名称补全
- IPv6 邻居表读取

## 验证标准

完成第一阶段后，macOS 上应满足：

- 不依赖 `ifconfig` 解析即可列出接口
- 不依赖 `arp` 解析即可列出 IPv4 邻居
- helper 缺失时自动回退旧路径
- 上层扫描 UI 和会话流程无须修改
