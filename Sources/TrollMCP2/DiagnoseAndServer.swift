import Foundation

// v2.9.71：自动诊断 + 本地 HTTP 服务
// 1. 自动诊断 — 启动failed/崩溃/注入failed自动判因，给出修复建议
// 2. 本地 HTTP 服务 — localhost REST API，其他脚本/工具可调用

// MARK: - 自动诊断工具

final class DiagnoseStartupTool: MCPTool {
    let definition = ToolDefinition(
        name: "diagnose.startup",
        summary: "Auto-diagnose why an app won't launch. Use for: app crashes on start, won't open, find out why. Don't use for: read crash logs (use shell.exec), inject dylib (use injection.enable). Example: user says '小红书 crashes on open' → diagnose startup failure.",
        parameters: [
            "bundle_id": "Target App bundle ID (required)",
            "auto_fix": "Auto try to fix (default false, just diagnose)"
        ],
        verified: true, category: "diagnose")

    func invoke(_ params: [String: Any]) throws -> [String: Any] {
        guard let bundleId = params["bundle_id"] as? String, !bundleId.isEmpty else {
            throw MCPError.invalidParams("bundle_id required")
        }
        let autoFix = (params["auto_fix"] as? Bool) ?? false

        var diagnosis: [String: Any] = ["bundle_id": bundleId]
        var causes: [String] = []
        var fixes: [String] = []

        // 1. 检查 App 是否存在
        let apps = AppCatalog.list()
        guard let target = apps.first(where: { $0.bundleId == bundleId }) else {
            return ["error": "App not installed: \(bundleId)", "fix": "reinstall with TrollStore"]
        }
        diagnosis["app_path"] = target.path

        // 2. 检查主二进制
        let exec = (NSDictionary(contentsOfFile: target.path.appending("/Info.plist"))?["CFBundleExecutable"] as? String) ?? ""
        let binaryPath = target.path.appending("/\(exec)")
        diagnosis["binary_exists"] = FileManager.default.fileExists(atPath: binaryPath)
        if !FileManager.default.fileExists(atPath: binaryPath) {
            causes.append("main binary does not exist")
            fixes.append("reinstall the App")
        }

        // 3. 检查架构 (v2.9.125：arch unknown = 解析failed (可能加密），不误判"非 arm64"）
        let (_, fileOutput) = InjectionManager.shared.spawnRoot("/usr/bin/file", args: [binaryPath])
        let isArm64 = fileOutput.contains("arm64")
        let isOtherArch = fileOutput.contains("x86_64") || fileOutput.contains("armv7") || fileOutput.contains("i386")
        if isArm64 {
            diagnosis["arch"] = "arm64"
        } else if isOtherArch {
            diagnosis["arch"] = "non-arm64"
        } else {
            diagnosis["arch"] = "unknown"
            diagnosis["arch_note"] = "parse failed (maybe encrypted or special Mach-O), does not mean unlaunchable/uninjectable; judge with cryptid"
        }
        if isOtherArch {
            causes.append("Not arm64 arch")
            fixes.append("Confirm the IPA is an arm64 build")
        }

        // 4. 检查签名
        let ldidPath = InjectionManager.shared.binaryPath("ldid") ?? ""
        if !ldidPath.isEmpty {
            let (_, entOutput) = InjectionManager.shared.spawnRoot(ldidPath, args: ["-e", binaryPath])
            diagnosis["signed"] = !entOutput.isEmpty
            if entOutput.isEmpty {
                causes.append("Binary not signed")
                fixes.append("Re-sign with ldid or reinstall via TrollStore")
            }
        }

        // 5. 检查注入状态和备份
        let backupPath = binaryPath.appending(".bak_macho")
        diagnosis["has_backup"] = FileManager.default.fileExists(atPath: backupPath)
        let frameworksDir = target.path.appending("/Frameworks")
        if let dylibs = try? FileManager.default.contentsOfDirectory(atPath: frameworksDir) {
            diagnosis["injected_dylibs"] = dylibs.filter { $0.hasSuffix(".dylib") }
        }

        // 6. 检查最近崩溃日志
        let crashDir = NSHomeDirectory().appending("/Library/Logs/CrashReporter")
        var recentCrash: String?
        if let files = try? FileManager.default.contentsOfDirectory(atPath: crashDir) {
            let relevant = files.filter { $0.contains(bundleId) || $0.contains(exec) }
            if let latest = relevant.sorted().last {
                recentCrash = crashDir.appending("/\(latest)")
                diagnosis["recent_crash"] = latest
                // 读取崩溃原因
                if let content = try? String(contentsOfFile: recentCrash!) {
                    let lines = content.components(separatedBy: .newlines)
                    for line in lines.prefix(30) {
                        if line.contains("Exception Type") || line.contains("Termination Reason") || line.contains("dyld") || line.contains("code signature") {
                            causes.append("Crash: \(line.trimmingCharacters(in: .whitespaces))")
                        }
                    }
                }
            }
        }

        // 7. 尝试启动并观察
        let _ = InjectionManager.shared.spawnRoot("/usr/bin/open", args: [bundleId])
        Thread.sleep(forTimeInterval: 3)
        let pid = findPid(by: bundleId)
        diagnosis["launch_pid"] = pid
        diagnosis["launched"] = pid > 0
        if pid == 0 {
            causes.append("Process gone within 3s of launch (crash)")
            fixes.append("Check dyld errors in the crash log — usually a missing dependency of the injected dylib")
        }

        // 8. 自动修复
        if autoFix && !causes.isEmpty {
            // 如果有备份且注入了 dylib，尝试恢复备份
            if FileManager.default.fileExists(atPath: backupPath) {
                let _ = InjectionManager.shared.spawnRoot("/bin/cp", args: [backupPath, binaryPath])
                fixes.append("Main binary backup restored")
            }
        }

        diagnosis["causes"] = causes
        diagnosis["fixes"] = fixes
        diagnosis["verdict"] = causes.isEmpty ? "✅ Startup OK" : "❌ Found \(causes.count) issues"
        // v2.9.125：CLI 式一句话结论
        diagnosis["message"] = causes.isEmpty
            ? "No startup issues found (arch=\(diagnosis["arch"] ?? "unknown"))"
            : "Found \(causes.count) issues: \(causes.prefix(3).joined(separator: "; "))"

        return diagnosis
    }
}

final class DiagnoseCrashTool: MCPTool {
    let definition = ToolDefinition(
        name: "diagnose.crash",
        summary: "Analyze app crash logs to find root cause. Use for: app keeps crashing, find out why. Don't use for: read raw crash log (use shell.exec), diagnose startup failure (use diagnose.startup). Example: user says '小红书 keeps crashing, why' → analyze crash.",
        parameters: [
            "bundle_id": "Target App bundle ID (required)",
            "count": "How many recent crashes to analyze (default 1)"
        ],
    verified: true, category: "diagnose")

    func invoke(_ params: [String: Any]) throws -> [String: Any] {
        guard let bundleId = params["bundle_id"] as? String, !bundleId.isEmpty else {
            throw MCPError.invalidParams("bundle_id required")
        }
        let count = (params["count"] as? Int) ?? 1

        let crashDir = NSHomeDirectory().appending("/Library/Logs/CrashReporter")
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: crashDir) else {
            return ["error": "cannot access crash log directory"]
        }

        let relevant = files.filter { $0.contains(bundleId) }.sorted().suffix(count)
        guard !relevant.isEmpty else {
            return ["bundle_id": bundleId, "result": "no crash log found"]
        }

        var analyses: [[String: Any]] = []
        for file in relevant {
            let path = crashDir.appending("/\(file)")
            guard let content = try? String(contentsOfFile: path) else { continue }

            var analysis: [String: Any] = ["file": file]
            let lines = content.components(separatedBy: .newlines)

            for line in lines {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("Exception Type:") {
                    analysis["exception_type"] = trimmed.replacingOccurrences(of: "Exception Type: ", with: "")
                } else if trimmed.hasPrefix("Exception Subtype:") {
                    analysis["exception_subtype"] = trimmed.replacingOccurrences(of: "Exception Subtype: ", with: "")
                } else if trimmed.hasPrefix("Termination Reason:") {
                    analysis["termination_reason"] = trimmed.replacingOccurrences(of: "Termination Reason: ", with: "")
                } else if trimmed.hasPrefix("Triggered by Thread:") {
                    analysis["crashed_thread"] = trimmed.replacingOccurrences(of: "Triggered by Thread: ", with: "")
                } else if trimmed.contains("dyld") && (trimmed.contains("error") || trimmed.contains("missing") || trimmed.contains("symbol")) {
                    analysis["dyld_error"] = trimmed
                } else if trimmed.contains("code signature") || trimmed.contains("invalid") {
                    analysis["signature_issue"] = trimmed
                }
            }

            // 提取崩溃线程调用栈 (前 10 帧）
            var inCrashedThread = false
            var stack: [String] = []
            for line in lines {
                if line.contains("Thread \(analysis["crashed_thread"] ?? "0") Crashed:") {
                    inCrashedThread = true
                    continue
                }
                if inCrashedThread {
                    if line.hasPrefix("Thread") && !line.contains("Crashed") { break }
                    if !line.isEmpty { stack.append(line.trimmingCharacters(in: .whitespaces)) }
                    if stack.count >= 10 { break }
                }
            }
            analysis["stack_top10"] = stack

            // 根因判断
            var rootCause = "unknown"
            if let term = analysis["termination_reason"] as? String {
                if term.contains("CODESIGNING") { rootCause = "Signing invalid" }
                else if term.contains("DYLD") { rootCause = "Dynamic library load failed" }
                else if term.contains("0xdead10cc") { rootCause = "Held a file lock while suspended in the background" }
            }
            if analysis["dyld_error"] != nil { rootCause = "dyld dependency missing or symbol not found" }
            if analysis["signature_issue"] != nil { rootCause = "Code signing issue" }
            analysis["root_cause"] = rootCause

            // 修复建议
            switch rootCause {
            case "Signing invalid":
                analysis["fix"] = "reinstall via TrollStore, or re-sign main binary with ldid -S"
            case "Dynamic library load failed", "dyld dependency missing or symbol not found":
                analysis["fix"] = "check injected dylib dependencies (otool -L), confirm all dependencies exist on device"
            case "Held a file lock while suspended in the background":
                analysis["fix"] = "close file handles and DB connections before App goes background"
            default:
                analysis["fix"] = "read full crash log and stack trace to locate the exact code"
            }

            analyses.append(analysis)
        }

        return [
            "bundle_id": bundleId,
            "crash_count": analyses.count,
            "analyses": analyses
        ]
    }
}

// MARK: - 本地未鉴权 LocalServerManager 已在安全加固版中移除


