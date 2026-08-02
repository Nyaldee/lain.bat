# lain.bat

<p align="center">
  <img src="lain.gif" alt="lain.bat">
</p>

*[Lire en français](README.fr.md)*

> [!CAUTION]
> Use at your own risk, without any warranty. Back up your files and create a restore point beforehand.

Personal, interactive batch script to optimize and de-bloat a fresh Windows 11
install: system/registry tweaks, NVIDIA configuration, power plan, disabling
unnecessary services and telemetry, and more — all through a menu-driven CLI,
no need to read the source to use it.

Recommended base: **Windows 11 IoT Enterprise LTSC 2024**

```
en-us_windows_11_iot_enterprise_ltsc_2024_x64_dvd_f6b14814.iso
```

## How to use

Execute this code in an elevated Command Prompt or download the script and
run it with administrator privileges.

```
curl -s -L -o %Temp%\lain.bat https://github.com/Nyaldee/lain.bat/raw/main/lain.bat && %Temp%\lain.bat
```

> [!NOTE]
> If you need a web browser.
> ```
> curl -s -L -o %userprofile%\desktop\brave_installer-x64.exe https://brave-browser-downloads.s3.brave.com/latest/brave_installer-x64.exe
> ```

## License

Copyright (C) 2026 Nyaldee. Licensed under the [GNU General Public License v3.0](LICENSE) — see the `LICENSE` file for the full text.
