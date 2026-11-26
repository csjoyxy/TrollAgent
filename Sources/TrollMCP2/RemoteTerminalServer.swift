import Foundation
import UIKit
import Network

/// v2.9.181：远程终端服务器——TrollAgent 自身暴露公网 HTTP API
///
/// 监听 0.0.0.0:8790 (可配置），N1 公网 IPv4 端口转发到手机局域网 IP 即可由云端 AI 直连：
///   - GET  /api/status     设备/版本/工具数/服务状态
///   - POST /api/tool       调用工具 (只读白名单 + 危险工具需设置授权）
///   - GET  /api/audit      工具执行审计链路 (OK/failed/耗时/错误码）
///   - GET  /api/crash      崩溃日志列表 + 全文
///   - GET  /api/tools      工具清单
///
/// 安全：Bearer token 鉴权；危险工具 (注入/删除/写入/启动/抓包等）默认拒绝，
/// 需在 设置 → 远程终端 显式开启"允许危险工具"。
/// 保活：开启服务后建议同时开启"后台常驻"，否则 App 被杀/深度挂起时服务不可达。
final class RemoteTerminalServer {
    static let shared = RemoteTerminalServer()
    private(set) var isRunning = false
    private var serverSocket: Int32 = -1
    private var acceptThread: Thread?

    private let defaultPort = 8790
    private let maxBody = 64 * 1024

    var port: Int {
        get {
            let p = UserDefaults.standard.integer(forKey: "remote_terminal_port")
            return p == 0 ? defaultPort : p
        }
        set { UserDefaults.standard.set(newValue, forKey: "remote_terminal_port") }
    }
    var token: String {
        get {
            let existing = UserDefaults.standard.string(forKey: "remote_terminal_token") ?? ""
            if existing.count >= 16 { return existing }
            let generated = LocalIPCAuth.generateRandomHex(bytesCount: 24)
            UserDefaults.standard.set(generated, forKey: "remote_terminal_token")
            return generated
        }
        set { UserDefaults.standard.set(newValue, forKey: "remote_terminal_token") }
    }
    var allowDangerous: Bool {
        get { UserDefaults.standard.bool(forKey: "remote_terminal_allow_dangerous") }
        set { UserDefaults.standard.set(newValue, forKey: "remote_terminal_allow_dangerous") }
    }
    var allowLAN: Bool {
        get { UserDefaults.standard.bool(forKey: "remote_terminal_allow_lan") }
        set { UserDefaults.standard.set(newValue, forKey: "remote_terminal_allow_lan") }
    }

    /// 默认拒绝策略：未开启 allowDangerous 时仅放行纯只读工具（防止新工具名绕过旧黑名单）
    private static let readOnlyAllowedTools: Set<String> = [
        "device", "diagnose", "diagnose.startup", "diagnose.crash",
        "conversations", "skills.list", "skills.read", "audit"
    ]
    private func isDangerous(_ name: String, params: [String: Any]) -> Bool {
        let lower = name.lowercased()
        guard Self.readOnlyAllowedTools.contains(lower) else { return true }
        let cmd = ((params["command"] as? String) ?? (params["action"] as? String) ?? "").lowercased()
        if lower == "device" {
            return !(cmd == "info" || cmd == "probe" || cmd == "snapshot")
        }
        return false
    }

    // MARK: - 生命周期

    func start() -> Bool {
        guard !isRunning else { return true }
        _ = token
        serverSocket = socket(AF_INET, SOCK_STREAM, 0)
        guard serverSocket >= 0 else { return false }
        var opt: Int32 = 1
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr.s_addr = allowLAN ? INADDR_ANY.bigEndian : INADDR_LOOPBACK.bigEndian
        let br = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverSocket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard br == 0 else { close(serverSocket); serverSocket = -1; return false }
        guard listen(serverSocket, 16) == 0 else { close(serverSocket); serverSocket = -1; return false }
        isRunning = true
        acceptThread = Thread { [weak self] in self?.acceptLoop() }
        acceptThread?.start()
        BackgroundKeepAlive.shared.start()
        if allowLAN, #available(iOS 14.0, *) {
            let browser = NWBrowser(for: .bonjour(type: "_trollagent._tcp", domain: nil), using: .tcp)
            browser.start(queue: DispatchQueue.main)
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { browser.cancel() }
        }
        return true
    }

    func stop() {
        isRunning = false
        if serverSocket >= 0 { close(serverSocket); serverSocket = -1 }
        acceptThread = nil
        // v2.9.183：服务关闭同步停止保活
        BackgroundKeepAlive.shared.stop()
    }

    private func acceptLoop() {
        // v6.1.5-14bz：请求处理串行化——原 DispatchQueue.global 并发执行 handleClient，
        // shell.exec 内共享状态（TrollRuntimeEngine.cwd、guestCwd 等）无锁并发修改 → 数据竞争 →
        // Segmentation fault 11（真机 CrashCatcher 记录 20+ 次）。改单串行队列，每次只处理一个
        // 连接，杜绝并发竞争；远程测试是逐条串行调用，串行处理无吞吐损失。
        var handlerQueue = DispatchQueue(label: "trollagent.remote-terminal.handler")
        while isRunning && serverSocket >= 0 {
            let client = accept(serverSocket, nil, nil)
            guard client >= 0 else { continue }
            // fix17: 单连接看门狗——串行队列 + 30s 处理超时。
            // 即使命令卡死在无法被 timeout 中断的系统调用（网络出站挂起等），
            // 看门狗也强制 close 释放队列：后续请求不再被永久排队，服务端最多堵 30s 自动恢复。
            let sem = DispatchSemaphore(value: 0)
            handlerQueue.async {
                self.handleClient(client)
                sem.signal()
            }
            let waitResult = sem.wait(timeout: .now() + 30)
            if waitResult == .timedOut {
                // 强制关闭：handleClient 内的 recv/send 立即返回错误 → 函数尽快退出 → 队列释放
                close(client)
                _ = sem.wait(timeout: .now() + 5)
                // fix22: 卡死在工具执行（posix_spawn/waitpid 卡内核不可中断状态）时 close 无效——
                // 旧 async 块仍占着 handlerQueue → 后续所有请求（含 health/echo）永久排队假死。
                // 重建队列丢弃卡死块：新连接立即进入新队列处理，服务端从假死自动恢复（最多堵 35s）。
                // 旧块若真卡在 waitpid 则无共享状态写入，重建后竞争风险可接受；若它后续又恢复写
                // 共享状态，重启 App 清理（卡死是异常路径，优先保服务可用）。
                handlerQueue = DispatchQueue(label: "trollagent.remote-terminal.handler")
            }
        }
    }

    // MARK: - HTTP 基础

    private struct HTTPRequest {
        var method = ""
        var path = ""
        var query: [String: String] = [:]
        var headers: [String: String] = [:]
        var body = ""
        var bearer = ""
    }

    private func readRequest(_ client: Int32) -> HTTPRequest? {
        var buf = [UInt8](repeating: 0, count: 8192)
        var raw = Data()
        // 读头部直到 \r\n\r\n (最多 32KB）
        var headerEnd = -1
        while raw.count < 32 * 1024 {
            let n = recv(client, &buf, buf.count, 0)
            guard n > 0 else { return nil }
            raw.append(contentsOf: buf[0..<n])
            if let range = raw.range(of: Data("\r\n\r\n".utf8)) {
                headerEnd = range.lowerBound
                break
            }
        }
        guard headerEnd >= 0 else { return nil }
        let headerData = raw.subdata(in: 0..<headerEnd)
        guard let headerStr = String(data: headerData, encoding: .utf8) else { return nil }
        var req = HTTPRequest()
        let lines = headerStr.components(separatedBy: "\r\n")
        guard let first = lines.first else { return nil }
        let parts = first.split(separator: " ")
        guard parts.count >= 2 else { return nil }
        req.method = String(parts[0])
        let urlPart = String(parts[1])
        let urlSplit = urlPart.split(separator: "?", maxSplits: 1)
        req.path = String(urlSplit[0])
        if urlSplit.count > 1 {
            for kv in String(urlSplit[1]).split(separator: "&") {
                let p = kv.split(separator: "=", maxSplits: 1)
                if p.count == 2 {
                    let k = String(p[0]).removingPercentEncoding ?? String(p[0])
                    let v = String(p[1]).removingPercentEncoding ?? String(p[1])
                    req.query[k] = v
                }
            }
        }
        for line in lines.dropFirst() {
            let kv = line.split(separator: ":", maxSplits: 1)
            if kv.count == 2 {
                let k = String(kv[0]).lowercased()
                let v = String(kv[1]).trimmingCharacters(in: .whitespaces)
                req.headers[k] = v
                if k == "authorization", v.hasPrefix("Bearer ") {
                    req.bearer = String(v.dropFirst(7))
                }
            }
        }
        // body
        if let cl = req.headers["content-length"], let n = Int(cl), n > 0 {
            let need = min(n, maxBody)
            while raw.count < headerEnd + 4 + need {
                let n2 = recv(client, &buf, buf.count, 0)
                guard n2 > 0 else { break }
                raw.append(contentsOf: buf[0..<n2])
            }
            let start = headerEnd + 4
            let end = min(raw.count, start + need)
            if end > start {
                req.body = String(data: raw.subdata(in: start..<end), encoding: .utf8) ?? ""
            }
        }
        return req
    }

    private func sendResponse(_ client: Int32, status: Int, body: String) {
        let data = Data(body.utf8)
        let reason: String
        switch status {
        case 200: reason = "OK"
        case 400: reason = "Bad Request"
        case 401: reason = "Unauthorized"
        case 403: reason = "Forbidden"
        case 404: reason = "Not Found"
        default: reason = "Error"
        }
        var resp = "HTTP/1.1 \(status) \(reason)\r\n"
        resp += "Content-Type: application/json; charset=utf-8\r\n"
        resp += "X-Content-Type-Options: nosniff\r\n"
        resp += "Content-Length: \(data.count)\r\n"
        resp += "Connection: close\r\n\r\n"
        let head = Data(resp.utf8)
        _ = head.withUnsafeBytes { send(client, $0.baseAddress, head.count, 0) }
        if data.count > 0 {
            _ = data.withUnsafeBytes { send(client, $0.baseAddress, data.count, 0) }
        }
    }

    private func json(_ obj: Any) -> String {
        (try? JSONSerialization.data(withJSONObject: obj, options: []))
            .flatMap { String(data: $0, encoding: .utf8) } ?? "{\"error\":\"serialize\"}"
    }

    // MARK: - 路由

    private func handleClient(_ client: Int32) {
        defer { close(client) }
        var rcvTimeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &rcvTimeout, socklen_t(MemoryLayout<timeval>.size))
        guard let req = readRequest(client) else { return }

        // 拦截浏览器跨域 / CSRF / DNS Rebinding 探测
        let isBrowserCrossOrigin = req.method.uppercased() == "OPTIONS"
            || req.headers["origin"] != nil
            || req.headers["referer"] != nil
            || req.headers.keys.contains(where: { $0.hasPrefix("sec-fetch-") })
        if isBrowserCrossOrigin {
            sendResponse(client, status: 403, body: json(["ok": false, "error": "browser_origin_forbidden"]))
            return
        }

        let expectedToken = token
        let authOK = !expectedToken.isEmpty && ConstantTime.equals(req.bearer, expectedToken)
        let path = req.path

        if path == "/health" {
            let build = (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String) ?? "unknown"
            sendResponse(client, status: 200, body: json(["ok": true, "service": "trollagent-remote-terminal", "version": appVersion(), "build": build]))
            return
        }
        guard authOK else {
            sendResponse(client, status: 401, body: json(["ok": false, "error": "unauthorized"]))
            return
        }

        switch (req.method, path) {
        case ("GET", "/api/status"):
            sendResponse(client, status: 200, body: statusJSON())
        case ("GET", "/api/tools"):
            sendResponse(client, status: 200, body: json(["ok": true, "count": ToolRegistry.shared.allToolNames().count, "tools": ToolRegistry.shared.allToolNames()]))
        case ("POST", "/api/tool"):
            handleTool(client, req)
        case ("GET", "/api/audit"):
            handleAudit(client, req)
        case ("GET", "/api/crash"):
            handleCrash(client, req)
        case ("GET", "/api/file"):
            handleFile(client, req)
        case ("GET", "/api/conversations"):
            handleConversations(client, req)
        case ("GET", "/api/conversation"):
            handleConversation(client, req)
        default:
            sendResponse(client, status: 404, body: json(["ok": false, "error": "no_route"]))
        }
    }

    /// v3.1.77：会话列表 (远程终端专用）
    private func handleConversations(_ client: Int32, _ req: HTTPRequest) {
        let limit = Int(req.query["limit"] ?? "10") ?? 10
        do {
            let r = try DebugDumpConversationsTool().invoke(["limit": limit])
            sendResponse(client, status: 200, body: json(["ok": true, "tool": "debug.dump_conversations", "result": r]))
        } catch {
            sendResponse(client, status: 200, body: json(["ok": false, "error": "\(error)"]))
        }
    }

    /// v3.1.77：单会话完整导出 (远程终端专用）
    private func handleConversation(_ client: Int32, _ req: HTTPRequest) {
        guard let title = req.query["title"], !title.isEmpty else {
            sendResponse(client, status: 400, body: json(["ok": false, "error": "title_required", "hint": "?title=<conversation title>"]))
            return
        }
        let limit = Int(req.query["limit"] ?? "50") ?? 50
        do {
            let r = try DebugDumpConversationTool().invoke(["title": title, "limit": limit])
            sendResponse(client, status: 200, body: json(["ok": true, "tool": "debug.dump_conversation", "result": r]))
        } catch {
            sendResponse(client, status: 200, body: json(["ok": false, "error": "\(error)"]))
        }
    }

    /// GET /api/file?path=<绝对路径>——规范化解析符号链接与 `..`，禁止读取私钥/令牌文件
    private func handleFile(_ client: Int32, _ req: HTTPRequest) {
        guard let p = req.query["path"], !p.isEmpty else {
            sendResponse(client, status: 400, body: json(["ok": false, "error": "path_required"]))
            return
        }
        let expanded = (p as NSString).expandingTildeInPath
        let canonical = URL(fileURLWithPath: expanded).resolvingSymlinksInPath().standardizedFileURL.path
        let allowedRoots: [String] = [
            URL(fileURLWithPath: NSHomeDirectory() + "/Documents/Workspace").resolvingSymlinksInPath().standardizedFileURL.path + "/",
            URL(fileURLWithPath: NSHomeDirectory() + "/Documents").resolvingSymlinksInPath().standardizedFileURL.path + "/",
        ]
        guard allowedRoots.contains(where: { canonical.hasPrefix($0) }) else {
            sendResponse(client, status: 403, body: json(["ok": false, "error": "path_denied", "hint": "only Documents/Workspace and Documents are allowed"]))
            return
        }
        let baseName = (canonical as NSString).lastPathComponent.lowercased()
        if baseName == ".ta_ipc_token" || baseName == "ca_key.pem" || baseName.hasSuffix(".key") || baseName.hasSuffix(".p12") {
            sendResponse(client, status: 403, body: json(["ok": false, "error": "sensitive_file_denied"]))
            return
        }
        guard let data = FileManager.default.contents(atPath: canonical) else {
            sendResponse(client, status: 404, body: json(["ok": false, "error": "not_found"]))
            return
        }
        let ext = (canonical as NSString).pathExtension.lowercased()
        let mime: String
        switch ext {
        case "png": mime = "image/png"
        case "jpg", "jpeg": mime = "image/jpeg"
        case "json": mime = "application/json"
        case "log", "txt", "md": mime = "text/plain; charset=utf-8"
        case "ipa", "tipa": mime = "application/octet-stream"
        case "zip": mime = "application/zip"
        default: mime = "application/octet-stream"
        }
        var head = "HTTP/1.1 200 OK\r\n"
        head += "Content-Type: \(mime)\r\n"
        head += "X-Content-Type-Options: nosniff\r\n"
        head += "Content-Length: \(data.count)\r\n"
        head += "Connection: close\r\n\r\n"
        let headData = Data(head.utf8)
        _ = headData.withUnsafeBytes { send(client, $0.baseAddress, headData.count, 0) }
        if data.count > 0 {
            _ = data.withUnsafeBytes { send(client, $0.baseAddress, data.count, 0) }
        }
    }

    private func appVersion() -> String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String) ?? "unknown"
    }

    private func statusJSON() -> String {
        let d = UIDevice.current
        var status: [String: Any] = [
            "ok": true,
            "service": "trollagent-remote-terminal",
            "app_version": appVersion(),
            "device_model": DeviceReporter.deviceModelIdentifier(),
            "device_name": d.model,
            "ios_version": d.systemVersion,
            "tools_count": ToolRegistry.shared.allToolNames().count,
            "port": port,
            "allow_dangerous": allowDangerous,
            "allow_lan": allowLAN,
        ]
        status["trollstore_detected"] = (try? FileManager.default.fileExists(atPath: "/var/containers/Bundle/Application")) ?? false
        return json(status)
    }

    private func handleTool(_ client: Int32, _ req: HTTPRequest) {
        guard let data = req.body.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            sendResponse(client, status: 400, body: json(["ok": false, "error": "bad_json"]))
            return
        }
        guard let name = obj["name"] as? String else {
            sendResponse(client, status: 400, body: json(["ok": false, "error": "name_required"]))
            return
        }
        let params = (obj["params"] as? [String: Any]) ?? [:]
        if isDangerous(name, params: params) && !allowDangerous {
            sendResponse(client, status: 403, body: json(["ok": false, "error": "remote_denied_dangerous", "hint": "dangerous tools require authorization in Settings -> Remote Terminal"]))
            return
        }
        let t0 = Date()
        do {
            let r = try ToolRegistry.shared.dispatch(name: name, params: params)
            var out = r
            out["_elapsed_ms"] = Int(Date().timeIntervalSince(t0) * 1000)
            let body = json(["ok": true, "tool": name, "result": out])
            sendResponse(client, status: 200, body: body)
        } catch {
            let body = json(["ok": false, "tool": name, "error": "\(error)"])
            sendResponse(client, status: 200, body: body)
        }
    }

    private func handleAudit(_ client: Int32, _ req: HTTPRequest) {
        let limit = Int(req.query["limit"] ?? "50") ?? 50
        let entries = AuditLog.shared.entries.prefix(max(1, min(limit, 200)))
        let out = entries.map { e -> [String: Any] in
            var d: [String: Any] = [
                "ts": Int(e.timestamp.timeIntervalSince1970),
                "category": e.category,
                "detail": String(e.detail.prefix(300)),
                "level": e.level.rawValue,
            ]
            if let s = e.status { d["status"] = s.rawValue }
            if let ms = e.elapsedMs { d["elapsed_ms"] = ms }
            if let ec = e.errorCode { d["error_code"] = ec }
            if let er = e.errorReason { d["error_reason"] = String(er.prefix(300)) }
            if let ns = e.nextStep { d["next_step"] = String(ns.prefix(200)) }
            return d
        }
        sendResponse(client, status: 200, body: json(["ok": true, "count": out.count, "entries": out]))
    }

    private func handleCrash(_ client: Int32, _ req: HTTPRequest) {
        let files = CrashCatcher.list()
        if let file = req.query["file"] {
            let safeName = (file as NSString).lastPathComponent
            guard !safeName.isEmpty, safeName == file else {
                sendResponse(client, status: 403, body: json(["ok": false, "error": "invalid_filename"]))
                return
            }
            let full = CrashCatcher.crashDir.appendingPathComponent(safeName)
            guard FileManager.default.fileExists(atPath: full.path) else {
                sendResponse(client, status: 404, body: json(["ok": false, "error": "not_found"]))
                return
            }
            sendResponse(client, status: 200, body: json(["ok": true, "file": safeName, "content": CrashCatcher.content(full.path)]))
            return
        }
        let limit = Int(req.query["limit"] ?? "20") ?? 20
        let list = files.prefix(max(1, min(limit, 50))).map { p -> [String: Any] in
            let name = URL(fileURLWithPath: p).lastPathComponent
            let content = CrashCatcher.content(p)
            let firstLine = content.split(separator: "\n").first.map(String.init) ?? ""
            return ["file": name, "head": String(firstLine.prefix(200)), "size": content.count]
        }
        sendResponse(client, status: 200, body: json(["ok": true, "count": list.count, "crashes": list]))
    }
}
