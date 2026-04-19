import Foundation

@main
struct LanScannerMacOSHelper {
    static func main() {
        let args = Array(CommandLine.arguments.dropFirst())
        CommandRouter.run(arguments: args)
    }
}
