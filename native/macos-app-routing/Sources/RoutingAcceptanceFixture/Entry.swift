import Foundation
import Darwin

@main
enum AcceptanceFixtureEntry {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        let arguments = Array(CommandLine.arguments.dropFirst())
        do {
            let runtime: FixtureRuntime
            let socketPath: String?
            switch arguments {
            case []: runtime = try FixtureRuntime(); socketPath = nil
            case ["--child"]: runtime = try FixtureRuntime(isChild: true); socketPath = nil
            default:
                guard arguments.count == 2, arguments[0] == "--socket" else { throw FixtureFailure.invalidRequest }
                runtime = try FixtureRuntime(); socketPath = arguments[1]
            }
            try runtime.run(socketPath: socketPath)
        } catch {
            // Only stable failure codes reach diagnostics; no input, address,
            // user configuration, environment or arbitrary OS error text.
            let code = (error as? FixtureFailure ?? .transport).code
            FileHandle.standardError.write(Data((code + "\n").utf8))
            exit(1)
        }
    }
}
