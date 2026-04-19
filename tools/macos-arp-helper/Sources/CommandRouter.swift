import Foundation

enum HelperExitCode {
    static let usage = 64
    static let unsupported = 78
}

enum CommandRouter {
    static func run(arguments: [String]) -> Never {
        guard arguments.count == 3, arguments[1] == "--contract" else {
            printUsageAndExit()
        }

        switch (arguments[0], arguments[2]) {
        case ("interfaces", InterfaceSnapshotContract.name):
            let rows = InterfaceSnapshotProvider.snapshot()
            LineProtocolEncoder.writeLines(rows.map(LineProtocolEncoder.encode))
            Foundation.exit(0)
        case ("neighbors", NeighborSnapshotContract.name):
            let rows = NeighborSnapshotProvider.snapshot()
            LineProtocolEncoder.writeLines(rows.map(LineProtocolEncoder.encode))
            Foundation.exit(0)
        default:
            fputs("unsupported command or contract\n", stderr)
            Foundation.exit(Int32(HelperExitCode.unsupported))
        }
    }

    private static func printUsageAndExit() -> Never {
        let usage = """
        usage:
          lanscanner-macos-arp-helper interfaces --contract \(InterfaceSnapshotContract.name)
          lanscanner-macos-arp-helper neighbors --contract \(NeighborSnapshotContract.name)
        """
        fputs("\(usage)\n", stderr)
        Foundation.exit(Int32(HelperExitCode.usage))
    }
}
