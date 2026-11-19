# lain.bat

<p align="center">
  <img src="lain.gif" alt="lain.bat">
</p>

*[Read in English](README.md) · [Lire en français](README.fr.md) · [日本語で読む](README.jp.md)*

> [!CAUTION]
> 使用风险自负，不提供任何担保。请事先备份文件并创建还原点。

一个个人用的交互式批处理脚本，用于优化和精简全新安装的 Windows 11：系统／注册表调整、NVIDIA 配置、电源计划、禁用不必要的服务和遥测等——全部通过菜单式命令行完成，无需阅读源代码即可使用。

推荐基础系统：**Windows 11 IoT Enterprise LTSC 2024**

```
en-us_windows_11_iot_enterprise_ltsc_2024_x64_dvd_f6b14814.iso
```

## 用法

在以管理员身份运行的命令提示符中执行以下代码，或下载脚本并以管理员权限运行。

```
curl -s -L -o %Temp%\lain.bat https://github.com/Nyaldee/lain.bat/raw/main/lain.bat && %Temp%\lain.bat
```

> [!NOTE]
> 如果你需要一个网页浏览器：
> ```
> curl -s -L -o %userprofile%\desktop\brave_installer-x64.exe https://brave-browser-downloads.s3.brave.com/latest/brave_installer-x64.exe
> ```

## 许可证

Copyright (C) 2026 Nyaldee。根据 [GNU General Public License v3.0](LICENSE) 授权，完整文本见 `LICENSE` 文件。
