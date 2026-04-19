import Foundation

struct InterfaceSnapshotContract {
    static let name = "interface-snapshot-v1"
}

struct NeighborSnapshotContract {
    static let name = "neighbor-snapshot-v1"
}

struct InterfaceRow {
    let id: String
    let name: String
    let ipv4: String
    let prefix: String
    let mac: String
    let type: String
    let isPrimary: String
}

struct NeighborRow {
    let ip: String
    let mac: String
    let hostname: String
    let mdnsName: String
}
