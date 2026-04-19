import Foundation

enum HelperExitCode {
    static let usage = 64
    static let unsupported = 78
}

enum CommandRouter {
    static func run(arguments: [String]) -> Never {
        if arguments.count == 3,
           arguments[1] == "--contract",
           arguments[0] == "interfaces",
           arguments[2] == InterfaceSnapshotContract.name
        {
            let rows = InterfaceSnapshotProvider.snapshot()
            LineProtocolEncoder.writeLines(rows.map(LineProtocolEncoder.encode))
            Foundation.exit(0)
        }

        if arguments.count == 3,
           arguments[1] == "--contract",
           arguments[0] == "neighbors",
           arguments[2] == NeighborSnapshotContract.name
        {
            let rows = NeighborSnapshotProvider.snapshot()
            LineProtocolEncoder.writeLines(rows.map(LineProtocolEncoder.encode))
            Foundation.exit(0)
        }

        if arguments.count == 5,
           arguments[0] == "neighbors-refresh",
           arguments[1] == "--contract",
           arguments[2] == NeighborRefreshContract.name,
           arguments[3] == "--ips"
        {
            let ips = arguments[4]
                .split(separator: ",")
                .map(String.init)
            let rows = NeighborSnapshotProvider.refresh(ips: ips)
            LineProtocolEncoder.writeLines(rows.map(LineProtocolEncoder.encode))
            Foundation.exit(0)
        }

        fputs("unsupported command or contract\n", stderr)
        Foundation.exit(Int32(HelperExitCode.unsupported))
    }

    private static func printUsageAndExit() -> Never {
        let usage = """
        usage:
          lanscanner-macos-arp-helper interfaces --contract \(InterfaceSnapshotContract.name)
          lanscanner-macos-arp-helper neighbors --contract \(NeighborSnapshotContract.name)
          lanscanner-macos-arp-helper neighbors-refresh --contract \(NeighborRefreshContract.name) --ips 192.168.1.10,192.168.1.11
        """
        fputs("\(usage)\n", stderr)
        Foundation.exit(Int32(HelperExitCode.usage))
    }
}
