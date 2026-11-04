<p align="center"><img src="assets/banner.png" alt="nikke-launcher-check" width="100%"></p>

# nikke-launcher-check

[한국어](README.md) | [English](README.en.md) | [日本語](README.ja.md) | [繁體中文](README.zh-Hant.md) | [简体中文](README.zh-Hans.md)

用于检查 2026 年 11 月报告的 NIKKE PC 启动器遭入侵事件已知痕迹的 Windows 工具。

- **只读：** 不删除、不更改、不关闭、不拦截、不外传，只显示警告。
- **不是清除工具。** 只报告痕迹，不会移除。
- **非官方。** 与 SHIFT UP、Level Infinite 无关。

> **“没有痕迹”不代表安全。** 仅检查已公开的指标。若在 2026 年 10 月 23 日 (GMT) 之后运行过启动器，无论结果如何都建议更改主要密码并退出会话。

> **验证状态：** v0.3.1 仅在模拟环境测试。注册表、签名和网络检查尚未在实际 Windows 验证。翻译为机器翻译，错误请通过 Issues 反馈。

## 使用方法

1. 从 [Releases](../../releases) 下载 zip 并解压。
2. 双击 `nikke_check.bat`，不需要管理员权限。
3. 请使用玩过 NIKKE 的 Windows 账户运行。
4. 结果会显示在屏幕上，并以 `NIKKE_check_日期_时间.txt` 保存到桌面。

## 选项

`-Language ko|en|ja|zh-Hant|zh-Hans`, `-NikkePath "D:\NIKKE"`, `-DeepScan`, `-AllUsers`

## 如果显示“危险”

关闭启动器或断开网络。删除 HKCU 键，重启，再只删除 64 位文件夹。切勿删除整个 PlatformExperienceHelper 文件夹或 HKLM 项。最安全的做法是重装 Windows。请在另一台干净设备上更改密码、启用双重验证、退出所有会话、重新签发令牌和密钥，并将加密资产转到新钱包。

---

来源：[MotherSphere 公开报告](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) 2026-11-04 02:00 GMT 版及评论中的受害报告。并非官方声明。采用 MIT 许可，不提供任何保证。
