import Darwin
import Foundation

enum NeighborSnapshotProvider {
    private static let udpPrimingPorts: [UInt16] = [33434, 5353, 137]
    private static let tcpPrimingPorts: [UInt16] = [22, 80, 443, 445]

    static func snapshot() -> [NeighborRow] {
        snapshotRows()
    }

    static func refresh(ips: [String]) -> [NeighborRow] {
        let targets = sanitizedRefreshTargets(ips)
        if !targets.isEmpty {
            primeNeighborCache(for: targets)
        }
        return snapshotRows()
    }

    private static func snapshotRows() -> [NeighborRow] {
        guard let buffer = routeSnapshotBuffer() else {
            return []
        }

        var rowsByIP: [String: NeighborRow] = [:]
        var offset = 0

        buffer.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return
            }

            while offset + MemoryLayout<rt_msghdr>.stride <= rawBuffer.count {
                let messageBase = base.advanced(by: offset)
                let header = messageBase.assumingMemoryBound(to: rt_msghdr.self).pointee
                let messageLength = Int(header.rtm_msglen)

                guard messageLength > 0, offset + messageLength <= rawBuffer.count else {
                    break
                }

                if let row = parseNeighborRow(messageBase: messageBase, header: header) {
                    rowsByIP[row.ip] = row
                }

                offset += messageLength
            }
        }

        return rowsByIP
            .values
            .sorted { left, right in
                compareIPv4Strings(left.ip, right.ip)
            }
    }

    private static func sanitizedRefreshTargets(_ ips: [String]) -> [String] {
        var seen = Set<String>()
        return ips
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { isUsableIPv4($0) }
            .filter { seen.insert($0).inserted }
    }

    private static func primeNeighborCache(for ips: [String]) {
        for ip in ips {
            runPing(ip: ip)
            sendUDPPriming(ip: ip)
            attemptTCPPriming(ip: ip)
        }
    }

    private static func runPing(ip: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/sbin/ping")
        process.arguments = ["-c", "1", "-W", "1000", ip]
        process.standardOutput = Pipe()
        process.standardError = Pipe()

        do {
            try process.run()
        } catch {
            return
        }

        let deadline = Date().addingTimeInterval(1.2)
        while process.isRunning && deadline.timeIntervalSinceNow > 0 {
            RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.05))
        }

        if process.isRunning {
            process.terminate()
        }
    }

    private static func sendUDPPriming(ip: String) {
        for port in udpPrimingPorts {
            guard var target = ipv4Sockaddr(ip: ip, port: port) else {
                continue
            }

            let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            if fd < 0 {
                continue
            }
            defer { close(fd) }

            var timeout = timeval(tv_sec: 0, tv_usec: 250_000)
            withUnsafePointer(to: &timeout) { pointer in
                _ = setsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_SNDTIMEO,
                    pointer,
                    socklen_t(MemoryLayout<timeval>.size)
                )
            }

            var payload: UInt8 = 0
            withUnsafePointer(to: &target) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    _ = withUnsafePointer(to: &payload) { payloadPointer in
                        sendto(
                            fd,
                            payloadPointer,
                            1,
                            0,
                            sockaddrPointer,
                            socklen_t(MemoryLayout<sockaddr_in>.size)
                        )
                    }
                }
            }
        }
    }

    private static func attemptTCPPriming(ip: String) {
        for port in tcpPrimingPorts {
            guard var target = ipv4Sockaddr(ip: ip, port: port) else {
                continue
            }

            let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
            if fd < 0 {
                continue
            }
            defer { close(fd) }

            let flags = fcntl(fd, F_GETFL, 0)
            if flags >= 0 {
                _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            }

            let connectResult = withUnsafePointer(to: &target) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }

            if connectResult == 0 {
                continue
            }

            if errno != EINPROGRESS {
                continue
            }

            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pollResult = poll(&descriptor, 1, 250)
            if pollResult <= 0 {
                continue
            }

            var socketError: Int32 = 0
            var errorLength = socklen_t(MemoryLayout<Int32>.size)
            if getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &errorLength) == 0 {
                _ = socketError
            }
        }
    }

    private static func routeSnapshotBuffer() -> [UInt8]? {
        var mib: [CInt] = [
            CTL_NET,
            PF_ROUTE,
            0,
            AF_INET,
            NET_RT_FLAGS,
            RTF_LLINFO,
        ]
        var length: size_t = 0

        let sizeResult = mib.withUnsafeMutableBufferPointer { mibBuffer in
            sysctl(mibBuffer.baseAddress, u_int(mibBuffer.count), nil, &length, nil, 0)
        }
        guard sizeResult == 0, length > 0 else {
            return nil
        }

        var buffer = [UInt8](repeating: 0, count: Int(length))
        let readResult = buffer.withUnsafeMutableBytes { rawBuffer in
            mib.withUnsafeMutableBufferPointer { mibBuffer in
                sysctl(
                    mibBuffer.baseAddress,
                    u_int(mibBuffer.count),
                    rawBuffer.baseAddress,
                    &length,
                    nil,
                    0
                )
            }
        }
        guard readResult == 0 else {
            return nil
        }

        let finalLength = Int(length)
        if buffer.count > finalLength {
            buffer.removeSubrange(finalLength..<buffer.count)
        }

        return buffer
    }

    private static func parseNeighborRow(
        messageBase: UnsafeRawPointer,
        header: rt_msghdr
    ) -> NeighborRow? {
        guard (Int32(header.rtm_flags) & RTF_LLINFO) != 0 else {
            return nil
        }

        var destinationIP: String?
        var macAddress: String?
        var cursor = messageBase.advanced(by: MemoryLayout<rt_msghdr>.stride)
        let addressMask = Int(header.rtm_addrs)

        for index in 0..<Int(RTAX_MAX) {
            guard (addressMask & (1 << index)) != 0 else {
                continue
            }

            let sockaddrPointer = cursor.assumingMemoryBound(to: sockaddr.self)
            let sockaddrValue = sockaddrPointer.pointee

            if index == Int(RTAX_DST) {
                destinationIP = ipv4String(from: sockaddrPointer)
            } else if index == Int(RTAX_GATEWAY) {
                macAddress = macAddressString(from: sockaddrPointer)
            }

            cursor = cursor.advanced(by: alignedSockaddrLength(sockaddrValue))
        }

        guard let ip = destinationIP,
              let mac = macAddress,
              isUsableIPv4(ip)
        else {
            return nil
        }

        return NeighborRow(
            ip: ip,
            mac: mac,
            hostname: "",
            mdnsName: ""
        )
    }

    private static func alignedSockaddrLength(_ address: sockaddr) -> Int {
        let rawLength = Int(address.sa_len)
        let baseLength = max(rawLength, MemoryLayout<UInt>.size)
        let alignment = MemoryLayout<UInt>.size
        return (baseLength + alignment - 1) & ~(alignment - 1)
    }

    private static func ipv4String(from sockaddrPointer: UnsafePointer<sockaddr>) -> String? {
        guard sockaddrPointer.pointee.sa_family == sa_family_t(AF_INET) else {
            return nil
        }

        let ipv4Pointer = UnsafeRawPointer(sockaddrPointer).assumingMemoryBound(to: sockaddr_in.self)
        var address = ipv4Pointer.pointee.sin_addr
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func macAddressString(from sockaddrPointer: UnsafePointer<sockaddr>) -> String? {
        guard sockaddrPointer.pointee.sa_family == sa_family_t(AF_LINK) else {
            return nil
        }

        let linkPointer = UnsafeRawPointer(sockaddrPointer).assumingMemoryBound(to: sockaddr_dl.self)
        return macAddressString(from: linkPointer)
    }

    private static func isUsableIPv4(_ value: String) -> Bool {
        var parsed = in_addr()
        guard inet_pton(AF_INET, value, &parsed) == 1 else {
            return false
        }

        let hostOrder = UInt32(bigEndian: parsed.s_addr)
        let firstOctet = (hostOrder >> 24) & 0xff
        let secondOctet = (hostOrder >> 16) & 0xff

        if value == "0.0.0.0" || firstOctet == 127 {
            return false
        }
        if firstOctet == 169 && secondOctet == 254 {
            return false
        }
        return true
    }

    private static func ipv4Sockaddr(ip: String, port: UInt16) -> sockaddr_in? {
        var address = in_addr()
        guard inet_pton(AF_INET, ip, &address) == 1 else {
            return nil
        }

        return sockaddr_in(
            sin_len: __uint8_t(MemoryLayout<sockaddr_in>.size),
            sin_family: sa_family_t(AF_INET),
            sin_port: in_port_t(port.bigEndian),
            sin_addr: address,
            sin_zero: (0, 0, 0, 0, 0, 0, 0, 0)
        )
    }

    private static func compareIPv4Strings(_ left: String, _ right: String) -> Bool {
        let leftParts = left.split(separator: ".").compactMap { Int($0) }
        let rightParts = right.split(separator: ".").compactMap { Int($0) }

        guard leftParts.count == 4, rightParts.count == 4 else {
            return left < right
        }

        for index in 0..<4 {
            if leftParts[index] != rightParts[index] {
                return leftParts[index] < rightParts[index]
            }
        }

        return left < right
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
}
