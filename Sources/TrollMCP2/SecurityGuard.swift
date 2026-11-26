import Foundation
import UIKit
import Security

// MARK: - Constant-Time Token Comparison

enum ConstantTime {
    static func equals(_ a: String, _ b: String) -> Bool {
        let ab = Array(a.utf8)
        let bb = Array(b.utf8)
        guard !ab.isEmpty, ab.count == bb.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<ab.count {
            diff |= (ab[i] ^ bb[i])
        }
        return diff == 0
    }
}

// MARK: - Per-Device Localhost IPC Authentication (ControlAgent / ProbeAgent / MemoryTweak)

final class LocalIPCAuth {
    static let shared = LocalIPCAuth()

    private let lock = NSLock()
    private var cachedToken: String?

    private var workspaceTokenPath: String {
        "/var/mobile/Documents/Workspace/.ta_ipc_token"
    }

    private init() {
        _ = token
    }

    var token: String {
        lock.lock()
        defer { lock.unlock() }
        if let t = cachedToken, t.count >= 32 {
            return t
        }
        let fm = FileManager.default
        let dir = (workspaceTokenPath as NSString).deletingLastPathComponent
        try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true)

        if let existing = try? String(contentsOfFile: workspaceTokenPath, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines),
           existing.count >= 32 {
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: workspaceTokenPath)
            cachedToken = existing
            return existing
        }

        let generated = Self.generateRandomHex(bytesCount: 32)
        if let data = generated.data(using: .utf8) {
            fm.createFile(atPath: workspaceTokenPath, contents: data, attributes: [.posixPermissions: 0o600])
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: workspaceTokenPath)
        }
        cachedToken = generated
        return generated
    }

    static func generateRandomHex(bytesCount: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: bytesCount)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytesCount, &bytes)
        if status != errSecSuccess {
            let fallback = UUID().uuidString.replacingOccurrences(of: "-", with: "") +
                           UUID().uuidString.replacingOccurrences(of: "-", with: "")
            return fallback.lowercased()
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    func authorize(_ request: inout URLRequest) {
        request.setValue(token, forHTTPHeaderField: "X-TA-Token")
        request.setValue("1", forHTTPHeaderField: "X-TA-Client")
    }

    /// Writes `.ta_ipc_token` into the target app's sandbox `Library/Caches/.ta_ipc_token`
    /// so injected loopback tweaks can verify requests without cross-app exposure.
    func provision(containerPath: String?) {
        let tok = token
        guard let container = containerPath, !container.isEmpty else { return }
        let cachesDir = (container as NSString).appendingPathComponent("Library/Caches")
        let dst = (cachesDir as NSString).appendingPathComponent(".ta_ipc_token")
        let fm = FileManager.default
        try? fm.createDirectory(atPath: cachesDir, withIntermediateDirectories: true)
        var wrote = false
        if let data = tok.data(using: .utf8),
           (try? data.write(to: URL(fileURLWithPath: dst), options: .atomic)) != nil {
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dst)
            wrote = true
        }
        if !wrote {
            _ = InjectionManager.shared.runAsRoot("mkdir", args: ["-p", cachesDir], timeout: 5)
            let cpName = ProcessInfo.processInfo.operatingSystemVersion.majorVersion <= 15 ? "cp-15" : "cp"
            let cpBin = InjectionManager.shared.binaryPath(cpName) != nil ? cpName : "cp"
            _ = InjectionManager.shared.runAsRoot(cpBin, args: ["-f", workspaceTokenPath, dst], timeout: 5)
        }
        _ = InjectionManager.shared.runAsRoot("chown", args: ["501:501", dst], timeout: 5)
    }

    func provision(bundleId: String) {
        _ = token
        if let app = AppCatalog.list().first(where: { $0.bundleId == bundleId }) {
            provision(containerPath: app.containerPath)
        }
    }

    func provision(pid: Int) {
        _ = token
        // Provision for all user apps whose executable matches or have containerPath
        var pathBuf = [CChar](repeating: 0, count: 4096)
        let len = proc_pidpath_shim(Int32(pid), &pathBuf, UInt32(pathBuf.count))
        if len > 0 {
            let execPath = String(cString: pathBuf)
            if let app = AppCatalog.list().first(where: { execPath.hasPrefix($0.path + "/") || execPath == $0.path }) {
                provision(containerPath: app.containerPath)
                return
            }
        }
    }
}

@_silgen_name("proc_pidpath")
private func proc_pidpath_shim(_ pid: Int32, _ buffer: UnsafeMutableRawPointer?, _ buffersize: UInt32) -> Int32

// MARK: - Central Security Policy & Human-in-the-Loop Gate

final class SecurityGuard: ObservableObject {
    static let shared = SecurityGuard()

    private enum Keys {
        static let confirmDangerous = "trollagent.sec.confirm_dangerous"
        static let blockExternalDylib = "trollagent.sec.block_external_dylib"
        static let officialUpdateOnly = "trollagent.sec.official_update_only"
        static let blockedCount = "trollagent.sec.blocked_count"
        static let lastBlocked = "trollagent.sec.last_blocked"
    }

    @Published var confirmDangerousTools: Bool {
        didSet { UserDefaults.standard.set(confirmDangerousTools, forKey: Keys.confirmDangerous) }
    }
    @Published var blockExternalDylibLoad: Bool {
        didSet { UserDefaults.standard.set(blockExternalDylibLoad, forKey: Keys.blockExternalDylib) }
    }
    @Published var officialUpdateOnly: Bool {
        didSet { UserDefaults.standard.set(officialUpdateOnly, forKey: Keys.officialUpdateOnly) }
    }
    @Published private(set) var blockedCount: Int
    @Published private(set) var lastBlockedReason: String

    private let trustLock = NSLock()
    private var trustedUntil: [String: Date] = [:]
    private let alertSerializeLock = NSLock()

    private init() {
        let ud = UserDefaults.standard
        confirmDangerousTools = (ud.object(forKey: Keys.confirmDangerous) as? Bool) ?? true
        blockExternalDylibLoad = (ud.object(forKey: Keys.blockExternalDylib) as? Bool) ?? true
        officialUpdateOnly = (ud.object(forKey: Keys.officialUpdateOnly) as? Bool) ?? true
        blockedCount = ud.integer(forKey: Keys.blockedCount)
        lastBlockedReason = ud.string(forKey: Keys.lastBlocked) ?? ""
    }

    func recordBlock(_ reason: String) {
        DispatchQueue.main.async {
            self.blockedCount += 1
            self.lastBlockedReason = reason
            UserDefaults.standard.set(self.blockedCount, forKey: Keys.blockedCount)
            UserDefaults.standard.set(reason, forKey: Keys.lastBlocked)
        }
        AuditLog.shared.log("security.block", detail: reason, level: .error)
    }

    /// Evaluates whether a tool call requires explicit user confirmation or hard-blocking.
    func checkToolExecution(name: String, params: [String: Any]) throws {
        let lower = name.lowercased()
        let cmd = ((params["command"] as? String) ?? (params["action"] as? String) ?? "").lowercased()

        // 1. Hard-block unverified in-process dylib loading unless explicitly unlocked
        if lower == "tool.load_dylib" || (lower == "inject" && cmd == "load_dylib") {
            if blockExternalDylibLoad {
                let msg = "已拦截加载外部 dylib 到 TrollAgent 宿主进程 (设置 → 安全防护中心 可管理)"
                recordBlock("load_dylib blocked")
                throw MCPError.failed(msg)
            }
        }

        // 2. Classify whether this invocation is high-risk
        guard let riskSummary = classifyHighRisk(tool: lower, subcommand: cmd, params: params) else {
            return
        }

        guard confirmDangerousTools else { return }
        // Only gate background AI / MCP / Remote threads; never block main UI thread
        guard !Thread.isMainThread else { return }

        // Check 5-minute temporary approval cache for this tool
        trustLock.lock()
        let expiry = trustedUntil[lower]
        trustLock.unlock()
        if let exp = expiry, exp > Date() {
            return
        }

        // Serialize UI confirmation prompts so concurrent tool calls never stack alerts
        alertSerializeLock.lock()
        defer { alertSerializeLock.unlock() }

        // Re-check trust after acquiring lock
        trustLock.lock()
        let expiryAfterWait = trustedUntil[lower]
        trustLock.unlock()
        if let exp = expiryAfterWait, exp > Date() {
            return
        }

        let decision = presentApprovalAlert(tool: name, summary: riskSummary)
        switch decision {
        case .allowOnce:
            AuditLog.shared.log("security.allow_once", detail: "\(name): \(riskSummary)")
        case .allowFiveMinutes:
            trustLock.lock()
            trustedUntil[lower] = Date().addingTimeInterval(300)
            trustLock.unlock()
            AuditLog.shared.log("security.allow_5m", detail: "\(name): \(riskSummary)")
        case .deny:
            recordBlock("\(name): \(riskSummary)")
            throw MCPError.failed("用户拒绝或超时拦截了高危操作：\(name) (\(riskSummary))")
        }
    }

    func revokeTemporaryTrust() {
        trustLock.lock()
        trustedUntil.removeAll()
        trustLock.unlock()
    }

    private func classifyHighRisk(tool: String, subcommand: String, params: [String: Any]) -> String? {
        if tool == "system.exec_root" {
            let p = (params["path"] as? String) ?? ""
            return "以 Root 权限执行原生二进制: \(p)"
        }
        if tool == "tool.load_dylib" {
            let p = (params["path"] as? String) ?? ""
            return "向宿主进程加载外部动态库: \(p)"
        }
        if tool == "inject" || tool.hasPrefix("injection.") {
            let mutating: Set<String> = ["enable", "enable_persisted", "mem", "load_dylib", "hook_apply", "keychain_wipe", "remove", "restore"]
            if subcommand.isEmpty || mutating.contains(subcommand) {
                let bid = (params["bundle_id"] as? String) ?? (params["path"] as? String) ?? ""
                return "应用注入/签名修改 (\(subcommand)): \(bid)"
            }
            return nil
        }
        if tool == "app" {
            let mutating: Set<String> = ["install", "uninstall", "replace_decrypted", "restore_binary", "cache_clear", "inject_package"]
            if mutating.contains(subcommand) {
                let bid = (params["bundle_id"] as? String) ?? (params["ipa_path"] as? String) ?? ""
                return "应用安装/卸载/替换 (\(subcommand)): \(bid)"
            }
            return nil
        }
        if tool == "bind_app_write" || tool == "app_write_file" {
            let bid = (params["bundle_id"] as? String) ?? (params["path"] as? String) ?? ""
            return "跨沙盒写入目标应用数据容器: \(bid)"
        }
        if tool == "ssh" {
            let host = (params["host"] as? String) ?? ""
            return "SSH 远程连接/传输 (\(subcommand)): \(host)"
        }
        if tool == "vpn.capture" && (subcommand == "start" || subcommand == "local_start") {
            return "开启系统级 HTTPS MITM 抓包 (\(subcommand))"
        }
        if tool == "network.capture" && subcommand == "start" {
            let bid = (params["bundle_id"] as? String) ?? ""
            return "开启注入式网络抓包: \(bid)"
        }
        if tool == "wifi_proxy" && subcommand == "set" {
            return "修改系统 WiFi 代理配置"
        }
        if tool == "user.mcp_add" {
            let u = (params["url"] as? String) ?? ""
            return "添加外部 MCP 服务器: \(u)"
        }
        if tool == "cleanup" || tool == "system.cleanup_execute" || (tool == "rescue" && subcommand != "scan") {
            return "执行系统/注入清理或恢复 (\(tool) \(subcommand))"
        }
        if tool == "memory" && (subcommand == "write" || subcommand == "freeze") {
            let addr = (params["address"] as? String) ?? ""
            return "修改目标进程内存 (\(subcommand)): \(addr)"
        }
        if tool == "shell.exec" {
            let raw = (params["command"] as? String) ?? ""
            if let reason = Self.shellRiskReason(raw) {
                let preview = String(raw.prefix(120))
                return "敏感 Shell 指令 [\(reason)]: \(preview)"
            }
            return nil
        }
        return nil
    }

    static func shellRiskReason(_ cmd: String) -> String? {
        let trimmed = cmd.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()
        if lower == "ta" || lower.hasPrefix("ta ") || lower.contains("; ta ") || lower.contains("&& ta ") || lower.contains("| ta ") {
            return "调用宿主原生工具 (ta)"
        }
        if lower.contains("keychain") || lower.contains("/var/keychains") {
            return "访问系统钥匙串路径"
        }
        if lower.contains("/ios_data_") || lower.contains("/containers/data/application") {
            return "访问其他 App 数据容器"
        }
        let exfilHints = ["curl ", "wget ", "nc ", "ncat ", "socat ", "scp ", "sftp ", "rsync "]
        if exfilHints.contains(where: { lower.contains($0) }) {
            let uploadFlags = ["-d ", "--data", "-f ", "--form", "-t ", "--upload", "--post", "post ", "put ", "nc ", "ncat ", "socat ", "scp ", "sftp "]
            if uploadFlags.contains(where: { lower.contains($0) }) {
                return "网络外发/上传数据"
            }
        }
        let mutatingTokens = [
            "rm ", "rm\t", "rmdir", "dd ", "mkfs", "chmod ", "chown ",
            "kill ", "killall", "pkill", "apk add", "apk del", "pip install", "pip3 install",
            "npm install", "npm i ", "git push", "sqlite_wipe", "opainject", "insert_dylib", "ct_bypass"
        ]
        for tok in mutatingTokens where lower.contains(tok) {
            return "文件删除/系统变更/包安装 (\(tok.trimmingCharacters(in: .whitespaces)))"
        }
        return nil
    }

    private enum ApprovalDecision {
        case allowOnce
        case allowFiveMinutes
        case deny
    }

    private func presentApprovalAlert(tool: String, summary: String) -> ApprovalDecision {
        let sem = DispatchSemaphore(value: 0)
        var result: ApprovalDecision = .deny
        var resolved = false
        let resolveLock = NSLock()

        func finish(_ d: ApprovalDecision) {
            resolveLock.lock()
            let shouldSignal = !resolved
            if shouldSignal {
                resolved = true
                result = d
            }
            resolveLock.unlock()
            if shouldSignal {
                sem.signal()
            }
        }

        var alertRef: UIAlertController?
        DispatchQueue.main.async {
            guard let topVC = Self.topViewController() else {
                // App is in background with no visible window: fail-closed!
                finish(.deny)
                return
            }
            let alert = UIAlertController(
                title: "安全审批：高权限操作",
                message: "工具：\(tool)\n详情：\(summary)\n\n请确认这是你本人预期的操作（60秒未操作将自动拦截）。",
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "允许本次", style: .default) { _ in
                finish(.allowOnce)
            })
            alert.addAction(UIAlertAction(title: "允许该工具 5 分钟", style: .default) { _ in
                finish(.allowFiveMinutes)
            })
            alert.addAction(UIAlertAction(title: "拦截拒绝", style: .destructive) { _ in
                finish(.deny)
            })
            alertRef = alert
            topVC.present(alert, animated: true)
        }

        let waitRes = sem.wait(timeout: .now() + 60)
        if waitRes == .timedOut {
            DispatchQueue.main.async {
                alertRef?.dismiss(animated: true)
            }
            finish(.deny)
        }
        return result
    }

    private static func topViewController() -> UIViewController? {
        guard UIApplication.shared.applicationState == .active else { return nil }
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let keyWin = scenes.flatMap { $0.windows }.first(where: { $0.isKeyWindow })
            ?? scenes.flatMap { $0.windows }.first
        guard var top = keyWin?.rootViewController else { return nil }
        while let presented = top.presentedViewController {
            top = presented
        }
        return top
    }
}
