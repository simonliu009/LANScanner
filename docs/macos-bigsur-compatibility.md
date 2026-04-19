# macOS Big Sur Compatibility Notes

## 目标

确保 LANScanner 的 macOS 原生 helper 可以在：

```text
macOS 11 (Big Sur)
```

上运行。

## 当前决策

helper 的 Swift Package deployment target 已设置为：

```text
macOS 11
```

对应文件：

- `tools/macos-arp-helper/Package.swift`

## 编译与运行的区别

需要区分两件事：

- 在 GitHub Actions 的较新 macOS runner 上编译
- 在用户的 Big Sur 机器上运行

只要 deployment target 维持在 `macOS 11`，就可以在较新的 runner 上构建出可在 Big Sur 运行的 helper。

## 第一阶段允许使用的能力

第一阶段只实现以下能力：

- 接口发现
- IPv4 邻居快照

推荐 API：

- `getifaddrs`
- `sysctl`
- `SystemConfiguration`
- `IOKit`

## 第一阶段避免使用的能力

为了降低 Big Sur 兼容风险，第一阶段避免：

- 依赖较新的 Network.framework 特性
- 依赖新版 Swift 宏或新语言特性
- 依赖只在 Ventura / Sonoma 后更稳定的 API

## 验证建议

后续 helper 一旦有真实实现，应至少验证：

1. 在较新的 macOS runner 上可编译
2. 在 Big Sur 真机上可以启动
3. `interfaces snapshot` 能返回至少一个 IPv4 接口
4. `neighbors snapshot` 能返回可解析的 IPv4 + MAC 记录

## 对主程序的提醒

helper 兼容 Big Sur 不等于整个 LANScanner 一定兼容 Big Sur。

仍需单独确认：

- Rust 主程序的最低 macOS 版本
- `iced` 及其依赖在 Big Sur 上的可运行性
- 打包后的 app bundle 是否包含正确的 helper 路径
