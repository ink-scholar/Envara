// Envara link router.
//
// A dockless helper registered as the system handler for web links. It exists
// for one reason: a link an application inside an environment hands to macOS
// (Notion's Google sign-in, for example) must be opened by that environment's
// browser, not by whatever browser the host desktop normally uses. macOS offers
// no per-application override, so the router reports the link and its sender to
// Envara, which answers with the browser to use. Every other case — Envara is
// not running, the sender is not part of an environment, Envara refuses or
// takes too long — goes to the browser that was the handler before this one,
// so the user's links keep working exactly as they did.
//
// It never changes any other setting, and it can be removed again from Envara,
// which restores that previous browser through macOS's own confirmation.
import AppKit
import Foundation

let applicationSupport = FileManager.default.homeDirectoryForCurrentUser
  .appendingPathComponent("Library/Application Support/Envara", isDirectory: true)
let stateURL = applicationSupport.appendingPathComponent("link-router.json")
/* A unix socket path is limited to 104 bytes, and the application-support path
 * is already longer than that, so the socket lives under the system temporary
 * directory with a per-user name. The socket itself is user-only (0600). */
let socketURL = URL(fileURLWithPath: "/tmp/io.envara.link-router.\(getuid()).sock")
let decisionTimeout: TimeInterval = 3.0
let idleExitSeconds: TimeInterval = 8.0

struct State: Codable {
  var previousHandler: String?
  var enabled: Bool?
}

func readState() -> State {
  guard let data = try? Data(contentsOf: stateURL),
        let state = try? JSONDecoder().decode(State.self, from: data) else { return State(previousHandler: nil, enabled: nil) }
  return state
}

func writeState(_ state: State) throws {
  try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: true,
    attributes: [.posixPermissions: 0o700])
  try JSONEncoder().encode(state).write(to: stateURL, options: [.atomic])
}

func currentHandlerIdentifier(_ scheme: String) -> String? {
  guard let probe = URL(string: "\(scheme)://envara.invalid/") else { return nil }
  return NSWorkspace.shared.urlForApplication(toOpen: probe).flatMap { Bundle(url: $0)?.bundleIdentifier }
}

func bundleIdentifier(of url: URL) -> String? { Bundle(url: url)?.bundleIdentifier }

/// The handler the user had before Envara was enabled, or the system default.
func fallbackApplication() -> URL? {
  if let previous = readState().previousHandler, !previous.isEmpty,
     let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: previous),
     bundleIdentifier(of: url) != Bundle.main.bundleIdentifier { return url }
  if let safari = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Safari") { return safari }
  return nil
}

func openOutsideEnvironment(_ urls: [URL], completion: @escaping (Bool) -> Void) {
  guard let application = fallbackApplication() else { completion(false); return }
  let configuration = NSWorkspace.OpenConfiguration()
  configuration.activates = true
  NSWorkspace.shared.open(urls, withApplicationAt: application, configuration: configuration) { _, error in
    completion(error == nil)
  }
}

/// Asks Envara what to do with a link. The answer is a small JSON object; any
/// failure, refusal or timeout leaves the link to the previous browser.
func decide(url: URL, sender: pid_t, timeout: TimeInterval = decisionTimeout) -> String? {
  let request: [String: Any] = ["url": url.absoluteString, "senderPid": Int(sender)]
  guard let body = try? JSONSerialization.data(withJSONObject: request) else { return nil }
  let socketPath = socketURL.path
  guard FileManager.default.fileExists(atPath: socketPath) else { return nil }
  let fd = socket(AF_UNIX, SOCK_STREAM, 0)
  if fd < 0 { return nil }
  defer { close(fd) }
  var address = sockaddr_un()
  address.sun_family = sa_family_t(AF_UNIX)
  address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
  let path = socketPath.utf8CString
  if path.count > MemoryLayout.size(ofValue: address.sun_path) { return nil }
  withUnsafeMutablePointer(to: &address.sun_path) { pointer in
    pointer.withMemoryRebound(to: CChar.self, capacity: path.count) { destination in
      for (index, byte) in path.enumerated() { destination[index] = byte }
    }
  }
  let connected = withUnsafePointer(to: &address) { pointer in
    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
      connect(fd, socketAddress, socklen_t(MemoryLayout<sockaddr_un>.size))
    }
  }
  if connected != 0 { return nil }
  var timeoutValue = timeval(tv_sec: Int(timeout), tv_usec: 0)
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeoutValue, socklen_t(MemoryLayout<timeval>.size))
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeoutValue, socklen_t(MemoryLayout<timeval>.size))
  let header = "POST /link HTTP/1.1\r\nhost: localhost\r\ncontent-length: \(body.count)\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
  var request_data = Data(header.utf8); request_data.append(body)
  if !writeAll(fd: fd, data: request_data) { return nil }
  let response = readAll(fd: fd)
  guard let separator = response.range(of: Data("\r\n\r\n".utf8)),
        let status = String(decoding: response[..<separator.lowerBound], as: UTF8.self).split(separator: "\r\n").first,
        status.contains(" 200 "),
        let answer = try? JSONSerialization.jsonObject(with: response[separator.upperBound...]) as? [String: Any] else { return nil }
  return answer["browser"] as? String
}

func writeAll(fd: Int32, data: Data) -> Bool {
  var offset = 0
  return data.withUnsafeBytes { raw -> Bool in
    guard let base = raw.baseAddress else { return false }
    while offset < data.count {
      let written = write(fd, base.advanced(by: offset), data.count - offset)
      if written <= 0 { return false }
      offset += written
    }
    return true
  }
}

func readAll(fd: Int32) -> Data {
  var data = Data(); var buffer = [UInt8](repeating: 0, count: 8192)
  while true {
    let count = read(fd, &buffer, buffer.count)
    if count <= 0 { break }
    data.append(contentsOf: buffer[0..<count])
    if data.count > 65536 { break }
  }
  return data
}

final class RouterDelegate: NSObject, NSApplicationDelegate {
  private var idleTimer: Timer?
  private var pending = 0

  func applicationWillFinishLaunching(_ notification: Notification) {
    NSAppleEventManager.shared().setEventHandler(self,
      andSelector: #selector(handleGetURL(_:withReply:)), forEventClass: AEEventClass(kInternetEventClass),
      andEventID: AEEventID(kAEGetURL))
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    scheduleIdleExit()
  }

  /// macOS delivers a link here, along with the process it came from. That
  /// process is what identifies the environment; the URL alone never does.
  @objc func handleGetURL(_ event: NSAppleEventDescriptor, withReply reply: NSAppleEventDescriptor) {
    guard let text = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue,
          let url = URL(string: text), let scheme = url.scheme?.lowercased(),
          scheme == "http" || scheme == "https" else {
      finish(urls: [], opened: false); return
    }
    var sender = pid_t(0)
    if let descriptor = event.attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr)) { sender = pid_t(descriptor.int32Value) }
    pending += 1
    idleTimer?.invalidate()
    var answered = false
    let answer = decide(url: url, sender: sender)
    answered = true
    if let browser = answer {
      FileHandle.standardError.write(Data("opened in \(browser)\n".utf8))
      _ = answered
      finish(urls: [], opened: true)
    } else {
      openOutsideEnvironment([url]) { _ in self.finish(urls: [], opened: true) }
    }
  }

  private func finish(urls: [URL], opened: Bool) {
    pending = max(0, pending - 1)
    if pending == 0 { scheduleIdleExit() }
  }

  private func scheduleIdleExit() {
    idleTimer?.invalidate()
    idleTimer = Timer.scheduledTimer(withTimeInterval: idleExitSeconds, repeats: false) { _ in
      NSApplication.shared.terminate(nil)
    }
  }
}

// Commands are handled before the app starts: they run from the command line,
// not from LaunchServices.
func runCommand(_ arguments: [String]) -> Int32? {
  switch arguments.first {
  case "--status":
    let state = readState()
    let handler = currentHandlerIdentifier("http")
    let mine = Bundle.main.bundleIdentifier ?? ""
    let enabled = handler == mine
    let payload: [String: Any] = ["enabled": enabled, "handler": handler ?? "", "router": mine,
      "previous": state.previousHandler ?? ""]
    if let data = try? JSONSerialization.data(withJSONObject: payload) { FileHandle.standardOutput.write(data) }
    return 0
  case "--enable":
    do {
      try FileManager.default.createDirectory(at: applicationSupport, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
      var state = readState()
      if state.enabled != true, let current = currentHandlerIdentifier("http"),
         current != Bundle.main.bundleIdentifier {
        state.previousHandler = current
      }
      let url = Bundle.main.bundleURL
      let group = DispatchGroup(); group.enter()
      var failure: String?
      NSWorkspace.shared.setDefaultApplication(at: url, toOpenURLsWithScheme: "http") { error in
        if let error { failure = error.localizedDescription }
        NSWorkspace.shared.setDefaultApplication(at: url, toOpenURLsWithScheme: "https") { secondError in
          if let secondError, failure == nil { failure = secondError.localizedDescription }
          group.leave()
        }
      }
      group.wait()
      state.enabled = failure == nil
      try writeState(state)
      print(failure == nil ? "enabled" : "refused: \(failure ?? "unknown")")
      return failure == nil ? 0 : 1
    } catch {
      print("refused: \(error.localizedDescription)")
      return 1
    }
  case "--disable":
    var state = readState()
    let restored = state.previousHandler
    if let identifier = restored, !identifier.isEmpty, let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) {
      let group = DispatchGroup(); group.enter()
      var failure: String?
      NSWorkspace.shared.setDefaultApplication(at: url, toOpenURLsWithScheme: "http") { error in
        if let error { failure = error.localizedDescription }
        NSWorkspace.shared.setDefaultApplication(at: url, toOpenURLsWithScheme: "https") { secondError in
          if let secondError, failure == nil { failure = secondError.localizedDescription }
          group.leave()
        }
      }
      group.wait()
      if failure != nil { print("refused: \(failure ?? "")"); return 1 }
    }
    state.enabled = false
    try? writeState(state)
    print("disabled")
    return 0
  default:
    return nil
  }
}

/* Local check: answer one link for a given sender pid, without LaunchServices.
 * Used by the desktop app's own verification; it never changes any setting. */
if CommandLine.arguments.contains("--dispatch"), let index = CommandLine.arguments.firstIndex(of: "--dispatch") {
  let url = CommandLine.arguments.count > index + 1 ? CommandLine.arguments[index + 1] : ""
  let sender = CommandLine.arguments.count > index + 2 ? pid_t(CommandLine.arguments[index + 2]) ?? 0 : 0
  if let parsed = URL(string: url), let browser = decide(url: parsed, sender: sender) {
    print("{\"opened\":\"environment\",\"browser\":\"browser\",\"name\":\(JSONEscape(browser))}")
  } else { print("{\"opened\":\"outside\"}") }
  exit(0)
}
func JSONEscape(_ value: String) -> String {
  let data = try? JSONSerialization.data(withJSONObject: [value])
  let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
  return String(text.dropFirst().dropLast())
}
if let code = runCommand(Array(CommandLine.arguments.dropFirst())) { exit(code) }
let application = NSApplication.shared
let delegate = RouterDelegate()
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
