//
//  DeviceReporter.swift
//  TrollAgent (Security-Hardened Edition)
//
//  安全加固：设备信息统计上报已彻底禁用（纯本地函数保留供状态展示，绝不外发任何设备信息）。
//

import Foundation
import UIKit

final class DeviceReporter {
    static let shared = DeviceReporter()

    private init() {}

    /// 已禁用远程统计上报（安全加固版不收集任何设备指纹）
    func reportIfNeeded() {
        // No-op by design in security-hardened build
    }

    /// 获取设备型号标识符，如 "iPhone14,5"（仅本地查询使用）
    static func deviceModelIdentifier() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        let identifier = machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
        return identifier
    }
}
