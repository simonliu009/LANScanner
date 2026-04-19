# macOS Native Network Helper

这个目录承载 LANScanner 的 macOS 原生网络 helper。

## 目标

helper 负责通过 macOS 原生 API 输出稳定的网络快照，避免主程序依赖：

- `ifconfig`
- `arp`
- `route`

主程序通过命令行调用 helper，并消费其标准输出。

## 系统兼容性

当前目标最低支持版本是：

```text
macOS 11 (Big Sur)
```

实现时应优先使用 Big Sur 已可用的 API：

- `Foundation`
- `getifaddrs`
- `sysctl`
- `SystemConfiguration`
- 基础 `IOKit`

应避免在第一阶段引入仅在较新 macOS 才可用的 Network.framework 新接口或其他高版本 API。

## 当前规划

第一阶段提供两个子命令：

- `interfaces snapshot --contract interface-snapshot-v1`
- `neighbors snapshot --contract neighbor-snapshot-v1`

第二阶段增加定向补刷命令：

- `neighbors-refresh --contract neighbor-refresh-v1 --ips ip1,ip2`

## 输出协议

### interfaces

每行一个接口，字段使用 `|` 分隔：

```text
id|name|ipv4|prefix|mac|type|is_primary
```

示例：

```text
en0|Wi-Fi|192.168.31.10|24|AA:BB:CC:DD:EE:FF|wifi|1
```

### neighbors

每行一个邻居，字段使用 `|` 分隔：

```text
ip|mac|hostname|mdns_name
```

示例：

```text
192.168.31.5|B8:27:EB:11:22:33|raspi|raspi.local
```

### neighbors-refresh

输入：

```text
neighbors-refresh --contract neighbor-refresh-v1 --ips 192.168.31.5,192.168.31.20
```

行为：

- helper 会先对指定 IP 做主动邻居缓存刷新
- 然后重新输出邻居快照
- 输出格式与 `neighbors` 相同

## 实现建议

- 接口发现：`getifaddrs` + `SCDynamicStore` / `SystemConfiguration`
- ARP / 邻居表：`sysctl(PF_ROUTE, NET_RT_FLAGS)` 或等效内核接口
- 接口主次判断：`IOKit` / `SystemConfiguration`

## 集成方式

产物建议命名为：

```text
lanscanner-macos-arp-helper
```

可执行文件放置优先级：

1. 环境变量 `LANSCANNER_MACOS_ARP_HELPER`
2. app 可执行文件同目录
3. `../Resources/`
4. `../Helpers/`
