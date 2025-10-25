#!/usr/bin/env python3
# wifi_password_gui.py
# Windows only (uses netsh). Dependencies: Python 3.8+
# Features: GUI list, current SSID highlight, Get password, copy to clipboard,
# timed clipboard clear, optional PIN auth (stored hashed locally), logging opt-in,
# CLI flags (--list, --current-only, --no-gui).

"""
Usage examples:
  python wifi_password_gui.py               # GUI
  python wifi_password_gui.py --no-gui --list         # list profiles (stdout)
  python wifi_password_gui.py --no-gui --current-only # print current connected SSID
  python wifi_password_gui.py --no-gui --get "MySSID"  # print password for SSID to stdout
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import threading
import time
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except Exception:
    tk = None  # headless mode may still be used

APP_NAME = "WiFi Password Viewer"
VERSION = "1.2"

# App data paths
APPDATA = Path(os.getenv("APPDATA") or Path.home() / ".config")
APP_DIR = APPDATA / "WifiPassViewer"
APP_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = APP_DIR / "config.json"
LOG_FILE = APP_DIR / "activity.log"
PIN_FILE = APP_DIR / "pin.json"

# Default config
DEFAULT_CONFIG = {
    "auto_clear_seconds": 15,
    "require_pin_for_reveal": False,
    "logging_enabled": False,
}

# Helper: read / write config
def load_config():
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    # write default
    save_config(DEFAULT_CONFIG)
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass

config = load_config()

# Logging (opt-in)
def log_event(event_type, detail=""):
    if not config.get("logging_enabled", False):
        return
    ts = datetime.utcnow().isoformat() + "Z"
    try:
        LOG_FILE.write_text(f"{ts}\t{event_type}\t{detail}\n", encoding="utf-8", append=True)
    except TypeError:
        # older Python doesn't support append in write_text
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts}\t{event_type}\t{detail}\n")

# Simple PIN storage (PBKDF2)
def set_pin(pin_text):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pin_text.encode("utf-8"), salt, 200_000)
    PIN_FILE.write_text(json.dumps({
        "salt": salt.hex(),
        "dk": dk.hex()
    }), encoding="utf-8")
    log_event("pin_set", "PIN configured")

def verify_pin(pin_text):
    if not PIN_FILE.exists():
        return False
    try:
        j = json.loads(PIN_FILE.read_text(encoding="utf-8"))
        salt = bytes.fromhex(j["salt"])
        dk = bytes.fromhex(j["dk"])
        candidate = hashlib.pbkdf2_hmac("sha256", pin_text.encode("utf-8"), salt, 200_000)
        return secrets.compare_digest(dk, candidate)
    except Exception:
        return False

def has_pin_configured():
    return PIN_FILE.exists()

# Run netsh and decode robustly
def run_netsh(args_list):
    if platform.system().lower() != "windows":
        raise RuntimeError("This program runs only on Windows (netsh dependent).")
    cmd = ["netsh"] + args_list
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        out = e.output or b""
    # try utf-8 then cp1252 fallback
    try:
        return out.decode("utf-8", errors="replace")
    except Exception:
        return out.decode("cp1252", errors="replace")

def get_profiles():
    out = run_netsh(["wlan", "show", "profiles"])
    profiles = []
    for line in out.splitlines():
        if ":" in line:
            left, right = line.split(":", 1)
            if "profile" in left.lower() or "perfil" in left.lower():
                name = right.strip().strip('"')
                if name:
                    profiles.append(name)
    # fallback loose parse
    if not profiles:
        for line in out.splitlines():
            if ":" in line:
                name = line.split(":",1)[1].strip().strip('"')
                if name:
                    profiles.append(name)
    # dedupe
    seen = set(); outlist=[]
    for p in profiles:
        if p not in seen:
            seen.add(p); outlist.append(p)
    return outlist

def get_current_connected_ssid():
    out = run_netsh(["wlan", "show", "interfaces"])
    for line in out.splitlines():
        if ":" in line:
            left, right = line.split(":",1)
            if left.strip().lower() in ("ssid","name"):
                ssid = right.strip().strip('"')
                if ssid and ssid.lower() != "n/a":
                    return ssid
    return None

def get_password_for_profile(profile_name):
    """
    Robust password parsing:
    - Prefer exact match for "Key Content" (English).
    - Then try normalized left-side (remove spaces) matching "keycontent".
    - Then fallback to several localized keywords (but avoid matching 'security key' which is a status).
    - If not found, include the full netsh output in the raised RuntimeError for diagnostics.
    """
    out = run_netsh(["wlan", "show", "profile", f'name="{profile_name}"', "key=clear"])
    # 1) Exact left == "key content"
    for line in out.splitlines():
        if ":" in line:
            left, right = line.split(":", 1)
            left_low = left.strip().lower()
            if left_low == "key content":
                pw = right.strip()
                if pw:
                    return pw
    # 2) Normalized check (in case of spacing differences like "KeyContent" / "key content")
    for line in out.splitlines():
        if ":" in line:
            left, right = line.split(":", 1)
            left_norm = left.strip().lower().replace(" ", "")
            if left_norm == "keycontent":
                pw = right.strip()
                if pw:
                    return pw
    # 3) Fallback candidates (localized keywords) - be careful not to match "security key"
    candidates = ["psk","clave","contraseña","password","passphrase","senha","motdepasse","mot de passe"]
    for line in out.splitlines():
        if ":" in line:
            left, right = line.split(":",1)
            left_low = left.strip().lower()
            # skip the "security key" status line explicitly
            if left_low.startswith("security key"):
                continue
            for cand in candidates:
                if cand in left_low:
                    maybe = right.strip()
                    if maybe:
                        return maybe
    # Not found: raise with full output for diagnostics
    raise RuntimeError("Could not parse password from netsh output.\n\nFull output:\n\n" + out)

# Clipboard helpers
def copy_to_clipboard(root, text):
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()  # ensure it sticks
        return True
    except Exception:
        return False

def clear_clipboard_after(root, seconds):
    def _clear():
        time.sleep(seconds)
        try:
            root.clipboard_clear()
        except Exception:
            pass
    t = threading.Thread(target=_clear, daemon=True)
    t.start()

# GUI class (Tkinter)
class WifiGui(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} — {VERSION}")
        self.geometry("640x420")
        self.resizable(False, False)
        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)
        header = ttk.Label(main, text="Wi‑Fi Profiles", font=("Segoe UI", 12, "bold"))
        header.pack(anchor=tk.W)
        self.info_label = ttk.Label(main, text="Select a profile and click 'Get password'. Run as Administrator if needed.")
        self.info_label.pack(anchor=tk.W, pady=(4,6))
        frame = ttk.Frame(main)
        frame.pack(fill=tk.BOTH, expand=True)
        self.list_var = tk.StringVar(value=[])
        self.listbox = tk.Listbox(frame, listvariable=self.list_var, height=12, width=70)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.listbox.yview)
        scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)
        controls = ttk.Frame(main)
        controls.pack(fill=tk.X, pady=(10,0))
        self.refresh_btn = ttk.Button(controls, text="Refresh", command=self.refresh_profiles)
        self.refresh_btn.pack(side=tk.LEFT)
        self.get_btn = ttk.Button(controls, text="Get password", command=self.on_get_password)
        self.get_btn.pack(side=tk.LEFT, padx=(6,0))
        self.copy_btn = ttk.Button(controls, text="Copy last password", command=self.copy_current_password)
        self.copy_btn.pack(side=tk.LEFT, padx=(6,0))
        self.settings_btn = ttk.Button(controls, text="Settings", command=self.open_settings)
        self.settings_btn.pack(side=tk.LEFT, padx=(6,0))
        self.quit_btn = ttk.Button(controls, text="Quit", command=self.destroy)
        self.quit_btn.pack(side=tk.RIGHT)
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(main, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(fill=tk.X, pady=(10,0))
        self.password_cache = None
        self.refresh_profiles(initial=True)

    def set_status(self, text):
        self.status_var.set(text); self.update_idletasks()

    def refresh_profiles(self, initial=False):
        try:
            self.set_status("Retrieving profiles...")
            profiles = get_profiles()
            self.listbox.delete(0, tk.END)
            current = get_current_connected_ssid()
            for p in profiles:
                display = p
                if current and p.lower() == current.lower():
                    display = f"{p}  (connected)"
                self.listbox.insert(tk.END, display)
            if not profiles:
                self.listbox.insert(tk.END, "<no profiles found>")
            self.password_cache = None
            self.set_status(f"Found {len(profiles)} profiles.")
            if initial:
                if self.listbox.size() > 0:
                    self.listbox.selection_set(0)
        except Exception as e:
            self.set_status("Error listing profiles")
            messagebox.showerror("Error", f"Failed to list Wi‑Fi profiles: {e}")

    def get_selected_profile_name(self):
        sel = self.listbox.curselection()
        if not sel:
            return None
        display = self.listbox.get(sel[0])
        if "  (connected)" in display:
            display = display.replace("  (connected)", "")
        return display.strip()

    def ask_for_pin_if_needed(self):
        if not config.get("require_pin_for_reveal", False):
            return True
        if not has_pin_configured():
            # ask to set one
            if not messagebox.askyesno("Set PIN", "No PIN configured. Would you like to set a PIN now?"):
                return False
            # set pin
            p1 = simpledialog.askstring("Set PIN", "Enter a numeric PIN (4-12 chars):", show="*")
            if not p1 or len(p1) < 4:
                messagebox.showwarning("Invalid", "PIN must be at least 4 characters.")
                return False
            p2 = simpledialog.askstring("Confirm PIN", "Confirm PIN:", show="*")
            if p1 != p2:
                messagebox.showerror("Mismatch", "PINs did not match.")
                return False
            set_pin(p1)
            messagebox.showinfo("Saved", "PIN saved locally (protected).")
            return True
        # verify
        pin = simpledialog.askstring("Enter PIN", "Enter PIN to reveal password:", show="*")
        if not pin:
            return False
        ok = verify_pin(pin)
        if not ok:
            messagebox.showerror("Denied", "PIN incorrect.")
        return ok

    def on_get_password(self):
        prof = self.get_selected_profile_name()
        if not prof or prof.startswith("<"):
            messagebox.showinfo("No profile", "Select a Wi‑Fi profile first.")
            return
        if not self.ask_for_pin_if_needed():
            return
        ok = messagebox.askyesno("Confirm", f"Reveal Wi‑Fi password for:\n\n{prof}\n\nProceed only on machines/networks you own.")
        if not ok:
            return
        try:
            self.set_status(f"Getting password for '{prof}'...")
            pw = get_password_for_profile(prof)
            self.password_cache = pw
            try:
                copy_to_clipboard(self, pw)
            except Exception:
                pass
            # optionally auto-clear
            secs = config.get("auto_clear_seconds", 15)
            if secs and isinstance(secs, int) and secs > 0:
                clear_clipboard_after(self, secs)
            log_event("reveal", prof)
            messagebox.showinfo("Password", f"Password for '{prof}':\n\n{pw}\n\n(Password copied to clipboard; will be cleared after {secs} seconds.)")
            self.set_status("Password retrieved.")
        except Exception as e:
            self.set_status("Failed to retrieve password")
            # include the full diagnostic (netsh output) if available
            if messagebox.askyesno("Error", f"Could not retrieve password: {e}\n\nShow diagnostic output?"):
                self.show_text_window("Diagnostic", str(e))

    def copy_current_password(self):
        if not self.password_cache:
            messagebox.showinfo("No password", "Click 'Get password' first.")
            return
        copy_to_clipboard(self, self.password_cache)
        clear_clipboard_after(self, config.get("auto_clear_seconds", 15))
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def open_settings(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.geometry("420x240")
        frame = ttk.Frame(win, padding=8)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Auto-clear clipboard (seconds):").pack(anchor=tk.W)
        auto_entry = ttk.Entry(frame)
        auto_entry.insert(0, str(config.get("auto_clear_seconds", 15)))
        auto_entry.pack(anchor=tk.W, pady=4)
        require_pin_var = tk.BooleanVar(value=config.get("require_pin_for_reveal", False))
        logging_var = tk.BooleanVar(value=config.get("logging_enabled", False))
        ttk.Checkbutton(frame, text="Require PIN to reveal passwords (local)", variable=require_pin_var).pack(anchor=tk.W, pady=4)
        ttk.Checkbutton(frame, text="Enable local logging (opt‑in)", variable=logging_var).pack(anchor=tk.W, pady=4)
        def save_and_close():
            try:
                v = int(auto_entry.get())
                config["auto_clear_seconds"] = max(0, v)
            except Exception:
                config["auto_clear_seconds"] = 15
            config["require_pin_for_reveal"] = bool(require_pin_var.get())
            config["logging_enabled"] = bool(logging_var.get())
            save_config(config)
            log_event("settings_saved", json.dumps(config))
            win.destroy()
        ttk.Button(frame, text="Save", command=save_and_close).pack(side=tk.RIGHT, pady=8)
        ttk.Button(frame, text="Cancel", command=win.destroy).pack(side=tk.RIGHT, padx=6, pady=8)

    def show_text_window(self, title, content):
        w = tk.Toplevel(self); w.title(title); w.geometry("640x420")
        txt = tk.Text(w, wrap=tk.NONE); txt.insert("1.0", content); txt.config(state=tk.DISABLED); txt.pack(fill=tk.BOTH, expand=True)
        sb = ttk.Scrollbar(w, orient=tk.VERTICAL, command=txt.yview); sb.pack(side=tk.RIGHT, fill=tk.Y); txt.config(yscrollcommand=sb.set)
        ttk.Button(w, text="Close", command=w.destroy).pack(pady=6)

# CLI / headless helpers
def cli_list_profiles():
    for p in get_profiles():
        print(p)

def cli_current_only():
    cur = get_current_connected_ssid()
    if cur:
        print(cur)
    else:
        print("")

def cli_get_profile(ssid):
    try:
        if config.get("require_pin_for_reveal", False):
            # require PIN in headless: ask on stdin
            if not has_pin_configured():
                print("PIN not configured. Please configure a PIN via the GUI first.", file=sys.stderr); sys.exit(2)
            pin = input("Enter PIN: ")
            if not verify_pin(pin):
                print("PIN incorrect.", file=sys.stderr); sys.exit(3)
        pw = get_password_for_profile(ssid)
        print(pw)
    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="WiFi Password Viewer (Windows)")
    parser.add_argument("--no-gui", action="store_true", help="Run headless (CLI only)")
    parser.add_argument("--list", action="store_true", help="List saved Wi-Fi profiles and exit")
    parser.add_argument("--current-only", action="store_true", help="Print currently connected SSID and exit")
    parser.add_argument("--get", metavar="SSID", help="Get password for SSID (headless)")
    args = parser.parse_args()

    if args.no_gui:
        if args.list:
            cli_list_profiles(); return
        if args.current_only:
            cli_current_only(); return
        if args.get:
            cli_get_profile(args.get); return
        # if --no-gui without specific action, default to list
        cli_list_profiles(); return

    # GUI mode
    if tk is None:
        print("Tkinter not available. Use --no-gui for CLI mode.", file=sys.stderr); sys.exit(1)
    app = WifiGui()
    app.mainloop()

if __name__ == "__main__":
    main()
