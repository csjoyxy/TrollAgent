import SwiftUI

// MARK: - 安全防护中心（替换原模拟 Coruna 安全盾，接入真实 SecurityGuard 策略门禁）
struct CorunaShieldView: View {
    @ObservedObject private var guardPolicy = SecurityGuard.shared
    @State private var trustRevokedToast = false

    private var allStrict: Bool {
        guardPolicy.confirmDangerousTools &&
        guardPolicy.blockExternalDylibLoad &&
        guardPolicy.officialUpdateOnly
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 14) {
                    Image(systemName: allStrict ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                        .font(.system(size: 40))
                        .foregroundColor(allStrict ? .green : .orange)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(allStrict ? "安全加固全量启用" : "部分高危防护已放宽")
                            .font(.headline)
                        Text("已拦截未授权/高危请求 \(guardPolicy.blockedCount) 次")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        if !guardPolicy.lastBlockedReason.isEmpty {
                            Text("最近拦截：\(guardPolicy.lastBlockedReason)")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                                .lineLimit(2)
                        }
                    }
                }
                .padding(.vertical, 6)
            }

            Section(header: Text("主动门禁策略（实时生效）")) {
                Toggle(isOn: $guardPolicy.confirmDangerousTools) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("高危工具人工弹窗审批 (HITL)")
                            .font(.body)
                        Text("AI / MCP / 远程调用 Root、注入、写容器、外发数据时必须经屏幕确认")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Toggle(isOn: $guardPolicy.blockExternalDylibLoad) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("禁止宿主加载外部 dylib 插件")
                            .font(.body)
                        Text("拦截 load_dylib / TARegisterTool 向 TrollAgent 自身注入未验证动态库")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Toggle(isOn: $guardPolicy.officialUpdateOnly) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("仅允许 GitHub 官方源 + SHA-256 校验更新")
                            .font(.body)
                        Text("禁用第三方反向代理镜像下载，防止安装包被中间人篡改")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Button(action: {
                    guardPolicy.revokeTemporaryTrust()
                    trustRevokedToast = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        trustRevokedToast = false
                    }
                }) {
                    HStack {
                        Image(systemName: trustRevokedToast ? "checkmark.circle.fill" : "lock.rotation")
                            .foregroundColor(trustRevokedToast ? .green : .blue)
                        Text(trustRevokedToast ? "已清空所有 5 分钟临时豁免" : "立即重置 5 分钟临时授权缓存")
                    }
                }
            }

            Section(header: Text("底层常驻加固项（不可关闭）")) {
                HardenedItemRow(
                    title: "本机插件通道强鉴权 (X-TA-Token)",
                    detail: "ControlAgent(4789) / ProbeAgent(4791) / MemoryTweak(8765) 强制校验随机密钥并拒绝浏览器跨源请求"
                )
                HardenedItemRow(
                    title: "GitHub 凭据严格域名隔离",
                    detail: "Bearer Token 仅发往 api.github.com，绝不随回退请求泄漏至 CDN 或镜像站"
                )
                HardenedItemRow(
                    title: "MITM 抓包上游系统证书校验",
                    detail: "使用 iOS SecTrust 校验真实服务器 TLS 证书链，杜绝抓包期间被上游中间人劫持"
                )
                HardenedItemRow(
                    title: "移除闭源黑盒二进制与漏洞样本",
                    detail: "已彻底剔除闭源 fuck_helper / fuck_vpn 与 Coruna 漏洞利用样本库"
                )
            }
        }
        .navigationTitle("安全防护中心")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct HardenedItemRow: View {
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.shield.fill")
                .foregroundColor(.green)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}
