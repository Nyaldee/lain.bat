# lain.bat

<p align="center">
  <img src="lain.gif" alt="lain.bat">
</p>

*[Read in English](README.md) · [Lire en français](README.fr.md) · [阅读中文版](README.zh-CN.md)*

> [!CAUTION]
> 自己責任で、いかなる保証もなくご使用ください。事前にファイルをバックアップし、復元ポイントを作成してください。

Windows 11 をクリーンインストールした直後に、最適化と不要な機能の削除を行うための、個人用の対話式バッチスクリプトです。システム／レジストリの調整、NVIDIA の設定、電源プラン、不要なサービスやテレメトリの無効化などを、すべてメニュー形式のコマンドラインから行えます。使うためにソースを読む必要はありません。

推奨ベース：**Windows 11 IoT Enterprise LTSC 2024**

```
en-us_windows_11_iot_enterprise_ltsc_2024_x64_dvd_f6b14814.iso
```

## 使い方

管理者として開いたコマンドプロンプトで次のコードを実行するか、スクリプトをダウンロードして管理者権限で実行してください。

```
curl -s -L -o %Temp%\lain.bat https://github.com/Nyaldee/lain.bat/raw/main/lain.bat && %Temp%\lain.bat
```

> [!NOTE]
> Web ブラウザーが必要な場合：
> ```
> curl -s -L -o %userprofile%\desktop\brave_installer-x64.exe https://brave-browser-downloads.s3.brave.com/latest/brave_installer-x64.exe
> ```

## ライセンス

Copyright (C) 2026 Nyaldee. [GNU General Public License v3.0](LICENSE) の下でライセンスされています。全文は `LICENSE` ファイルをご覧ください。
