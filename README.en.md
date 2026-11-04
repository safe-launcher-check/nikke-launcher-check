<p align="center"><img src="assets/banner.png" alt="nikke-launcher-check" width="100%"></p>

# nikke-launcher-check

[한국어](README.md) | [English](README.en.md) | [日本語](README.ja.md) | [繁體中文](README.zh-Hant.md) | [简体中文](README.zh-Hans.md)

Windows checker for known traces of the NIKKE PC launcher compromise reported in November 2026.

- **Read-only:** deletes nothing, changes nothing, closes nothing, blocks nothing, sends nothing. Warnings only.
- **Not a removal tool.** It reports traces and does not remove them.
- **Unofficial.** Not affiliated with SHIFT UP or Level Infinite.

> **"No traces" does not mean safe.** Only published indicators are checked. If you ran the launcher after Oct 23, 2026 (GMT), changing key passwords and signing out of sessions is recommended regardless of the result.

> **Verification:** v0.3.0 was tested only in simulated environments. Registry, signature and network checks are not yet verified on real Windows. Translations are machine-made; report errors via Issues.

## Usage

1. Download the zip from [Releases](../../releases) and extract it.
2. Double-click `nikke_check.bat`. Admin rights are not needed.
3. Run it on the Windows account that used NIKKE.
4. The result appears on screen and is saved to your Desktop as `NIKKE_check_<date>_<time>.txt`.

## Options

`-Language ko|en|ja|zh-Hant|zh-Hans`, `-NikkePath "D:\NIKKE"`, `-DeepScan`, `-AllUsers`

## If DANGER appears

Close the launcher or disconnect. Delete the HKCU key, restart, then delete only the 64-hex folder. Do not delete the whole PlatformExperienceHelper folder or the HKLM entry. Reinstalling Windows is safest. From a clean device, change passwords, enable 2FA, sign out of all sessions, reissue tokens and keys, and move crypto to a new wallet.

---

Source: [MotherSphere public report](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5), 2026-11-04 02:00 GMT revision, and victim reports in its comments. Not an official statement. Provided under the MIT license with no warranty.
