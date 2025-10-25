WiFi Password Viewer (Windows)
Version: 1.2
Author: Anagh Barnwal
License: MIT

----------------------------------------
Description:
----------------------------------------
WiFi Password Viewer is a Windows utility that allows you to view saved Wi-Fi passwords for profiles stored on your machine. It provides a GUI for easy selection and copy, optional PIN protection, and clipboard auto-clear.

----------------------------------------
Features:
----------------------------------------
- Lists all saved Wi-Fi profiles
- Highlights currently connected network
- Reveals passwords when you click "Get password"
- Copies password to clipboard (auto-clears after configurable seconds)
- Optional PIN protection for revealing passwords
- Optional local logging of activity (opt-in)
- Headless/CLI mode:
  --list            List saved Wi-Fi profiles
  --current-only    Show currently connected SSID
  --get "SSID"      Get password for a specific SSID (requires PIN if enabled)
- Simple configuration stored in %APPDATA%\WifiPassViewer

----------------------------------------
Usage:
----------------------------------------
Run the EXE:
- GUI: double-click the exe
- CLI: open cmd and run:
  wifi_password_viewer.exe --no-gui --list
  wifi_password_viewer.exe --no-gui --current-only
  wifi_password_viewer.exe --no-gui --get "MySSID"

Administrator privileges may be required to view some passwords.

----------------------------------------
Security & Privacy:
----------------------------------------
- Only reveal Wi-Fi passwords on machines/networks you own.
- The app stores config and optional PIN locally in %APPDATA%\WifiPassViewer.
- No passwords or logs are transmitted externally.

----------------------------------------
Installation:
----------------------------------------
- Download the EXE from the release page.
- Optional: Run as Administrator for full access.
- Optional: Configure settings and PIN in GUI.

----------------------------------------
Disclaimer:
----------------------------------------
This software is provided "as-is" for educational and personal use. Use responsibly. The author is not responsible for misuse.
