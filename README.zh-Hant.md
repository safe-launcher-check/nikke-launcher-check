<p align="center"><img src="assets/banner.png" alt="nikke-launcher-check" width="100%"></p>

# nikke-launcher-check

[한국어](README.md) | [English](README.en.md) | [日本語](README.ja.md) | [繁體中文](README.zh-Hant.md) | [简体中文](README.zh-Hans.md)

用於檢查 2026 年 11 月報告的 NIKKE PC 啟動器遭入侵事件已知痕跡的 Windows 工具。

- **唯讀：** 不刪除、不變更、不關閉、不封鎖、不外傳，只顯示警告。
- **不是清除工具。** 只回報痕跡，不會移除。
- **非官方。** 與 SHIFT UP、Level Infinite 無關。

> **「沒有痕跡」不代表安全。** 僅檢查已公開的指標。若在 2026 年 10 月 23 日 (GMT) 之後執行過啟動器，無論結果如何都建議變更主要密碼並登出工作階段。

> **驗證狀態：** v0.3.0 僅在模擬環境測試。登錄檔、簽章與網路檢查尚未在實際 Windows 驗證。翻譯為機器翻譯，錯誤請透過 Issues 回報。

## 使用方式

1. 從 [Releases](../../releases) 下載 zip 並解壓縮。
2. 雙擊 `nikke_check.bat`，不需要系統管理員權限。
3. 請使用玩過 NIKKE 的 Windows 帳戶執行。
4. 結果會顯示在畫面上，並以 `NIKKE_check_日期_時間.txt` 儲存到桌面。

## 選項

`-Language ko|en|ja|zh-Hant|zh-Hans`, `-NikkePath "D:\NIKKE"`, `-DeepScan`, `-AllUsers`

## 如果顯示「危險」

關閉啟動器或中斷網路。刪除 HKCU 機碼，重新開機，再只刪除 64 位資料夾。切勿刪除整個 PlatformExperienceHelper 資料夾或 HKLM 項目。最安全的做法是重新安裝 Windows。請在另一台乾淨裝置上變更密碼、啟用雙重驗證、登出所有工作階段、重新核發權杖與金鑰，並將加密資產轉到新錢包。

---

來源：[MotherSphere 公開報告](https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5) 2026-11-04 02:00 GMT 版及留言中的受害回報。並非官方聲明。採 MIT 授權，不提供任何保證。
