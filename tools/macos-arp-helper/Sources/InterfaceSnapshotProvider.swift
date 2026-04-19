import Darwin
import Foundation
import SystemConfiguration

enum InterfaceSnapshotProvider {
    static func snapshot() -> [InterfaceRow] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else {
            return []
        }
        defer { freeifaddrs(head) }

        let primaryInterface = primaryInterfaceName()
        var entriesByName: [String: InterfaceAccumulator] = [:]

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let entry = current.pointee
            guard let rawName = entry.ifa_name else {
                cursor = entry.ifa_next
                continue
            }

            let name = String(cString: rawName)
            let flags = Int32(entry.ifa_flags)

            if shouldSkipInterface(name: name, flags: flags) {
                cursor = entry.ifa_next
                continue
            }

            let family = entry.ifa_addr?.pointee.sa_family
            var accumulator = entriesByName[name] ?? InterfaceAccumulator(name: name)

            switch family {
            case sa_family_t(AF_INET):
                if let ipv4 = ipv4String(from: entry.ifa_addr),
                   let prefix = prefixLength(from: entry.ifa_netmask)
                {
                    accumulator.ipv4 = ipv4
                    accumulator.prefix = String(prefix)
                }
            case sa_family_t(AF_LINK):
                if let mac = macAddressString(from: entry.ifa_addr) {
                    accumulator.mac = mac
                }
            default:
                break
            }

            entriesByName[name] = accumulator
            cursor = entry.ifa_next
        }

        return entriesByName
            .values
            .compactMap { accumulator in
                guard let ipv4 = accumulator.ipv4,
                      let prefix = accumulator.prefix,
                      let mac = accumulator.mac
                else {
                    return nil
                }

                let ifaceType = interfaceType(for: accumulator.name)
                return InterfaceRow(
                    id: accumulator.name,
                    name: displayName(for: accumulator.name, type: ifaceType),
                    ipv4: ipv4,
                    prefix: prefix,
                    mac: mac,
                    type: ifaceType,
                    isPrimary: accumulator.name == primaryInterface ? "1" : "0"
                )
            }
            .sorted { left, right in
                if left.isPrimary != right.isPrimary {
                    return left.isPrimary > right.isPrimary
                }
                return left.id < right.id
            }
    }

    private static func primaryInterfaceName() -> String? {
        let store = SCDynamicStoreCreate(nil, "lanscanner-macos-arp-helper" as CFString, nil, nil)
        guard let store else {
            return nil
        }

        let globalIPv4Key = "State:/Network/Global/IPv4" as CFString
        guard let value = SCDynamicStoreCopyValue(store, globalIPv4Key) else {
            return nil
        }

        let dictionary = value as NSDictionary
        return dictionary["PrimaryInterface"] as? String
    }

    private static func shouldSkipInterface(name: String, flags: Int32) -> Bool {
        if (flags & IFF_UP) == 0 || (flags & IFF_RUNNING) == 0 {
            return true
        }
        if (flags & IFF_LOOPBACK) != 0 {
            return true
        }
        return name.hasPrefix("awdl")
            || name.hasPrefix("llw")
            || name.hasPrefix("utun")
            || name.hasPrefix("bridge")
    }

    private static func ipv4String(from address: UnsafeMutablePointer<sockaddr>?) -> String? {
        guard let address else {
            return nil
        }

        let copyLength = sockaddrCopyLength(address.pointee)
        guard copyLength > 0 else {
            return nil
        }

        var storage = sockaddr_storage()
        memcpy(&storage, address, copyLength)

        guard storage.ss_family == sa_family_t(AF_INET) else {
            return nil
        }

        return withUnsafePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ipv4Pointer in
                var addr = ipv4Pointer.pointee.sin_addr
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                    return nil
                }
                return String(cString: buffer)
            }
        }
    }

    private static func prefixLength(from netmask: UnsafeMutablePointer<sockaddr>?) -> Int? {
        guard let netmask else {
            return nil
        }

        let copyLength = sockaddrCopyLength(netmask.pointee)
        guard copyLength > 0 else {
            return nil
        }

        var storage = sockaddr_storage()
        memcpy(&storage, netmask, copyLength)

        guard storage.ss_family == sa_family_t(AF_INET) else {
            return nil
        }

        return withUnsafePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { ipv4Pointer in
                let mask = UInt32(bigEndian: ipv4Pointer.pointee.sin_addr.s_addr)
                var prefix = 0
                var seenZero = false

                for bit in 0..<32 {
                    let isSet = (mask & (1 << (31 - bit))) != 0
                    if isSet {
                        if seenZero {
                            return nil
                        }
                        prefix += 1
                    } else {
                        seenZero = true
                    }
                }

                return prefix
            }
        }
    }

    private static func macAddressString(from address: UnsafeMutablePointer<sockaddr>?) -> String? {
        guard let address else {
            return nil
        }

        return withUnsafePointer(to: address.pointee) { pointer in
            pointer.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { linkPointer in
                macAddressString(from: linkPointer)
            }
        }
    }

    private static func interfaceType(for name: String) -> String {
        let lowercased = name.lowercased()

        if lowercased.hasPrefix("en") {
            if name == "en0" {
                return "wifi"
            }
            return "ethernet"
        }
        if lowercased.contains("bridge") || lowercased.contains("docker") {
            return "docker"
        }
        return "other"
    }

    private static func displayName(for name: String, type: String) -> String {
        switch type {
        case "wifi":
            return "Wi-Fi (\(name))"
        case "ethernet":
            return "Ethernet (\(name))"
        case "docker":
            return "Docker (\(name))"
        default:
            return name
        }
    }

    private static func macAddressString(from linkPointer: UnsafePointer<sockaddr_dl>) -> String? {
        let link = linkPointer.pointee
        guard Int(link.sdl_alen) == 6 else {
            return nil
        }

        let nameLength = Int(link.sdl_nlen)
        let dataLength = Int(link.sdl_alen)
        let dataOffset = MemoryLayout<sockaddr_dl>.offset(of: \.sdl_data) ?? 0
        let dataBase = UnsafeRawPointer(linkPointer)
            .advanced(by: dataOffset)
            .assumingMemoryBound(to: UInt8.self)

        let macBytes = Array(
            UnsafeBufferPointer(
                start: dataBase.advanced(by: nameLength),
                count: dataLength
            )
        )
        guard macBytes.count == 6 else {
            return nil
        }

        return macBytes
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
    }

    private static func sockaddrCopyLength(_ address: sockaddr) -> Int {
        let rawLength = Int(address.sa_len)
        if rawLength > 0 {
            return rawLength
        }
        return MemoryLayout<sockaddr>.size
    }
}

private struct InterfaceAccumulator {
    let name: String
    var ipv4: String?
    var prefix: String?
    var mac: String?
}
