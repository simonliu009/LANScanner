import Foundation

enum LineProtocolEncoder {
    static func encode(_ row: InterfaceRow) -> String {
        [
            row.id,
            row.name,
            row.ipv4,
            row.prefix,
            row.mac,
            row.type,
            row.isPrimary,
        ]
        .map(escape)
        .joined(separator: "|")
    }

    static func encode(_ row: NeighborRow) -> String {
        [
            row.ip,
            row.mac,
            row.hostname,
            row.mdnsName,
        ]
        .map(escape)
        .joined(separator: "|")
    }

    static func writeLines(_ lines: [String]) {
        guard !lines.isEmpty else {
            return
        }

        let payload = lines.joined(separator: "\n") + "\n"
        FileHandle.standardOutput.write(Data(payload.utf8))
    }

    private static func escape(_ value: String) -> String {
        value.replacingOccurrences(of: "|", with: " ")
    }
}
