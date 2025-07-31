import tkinter as tk
from tkinter import messagebox
import os
import ctypes
import getpass
import winreg
import webbrowser
import time
import string
import sys
# ✅ Check for admin rights
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ✅ Disable USB ports
def disable_usb():
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 4)
        winreg.CloseKey(reg_key)
        print("🔒 USB ports disabled.")
    except Exception as e:
        print(f"Error disabling USB: {e}")

# ✅ Enable USB ports
def enable_usb():
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 3)
        winreg.CloseKey(reg_key)
        print("🔓 USB ports enabled.")
    except Exception as e:
        print(f"Error enabling USB: {e}")

# ✅ Get all current logical drives (C:\, D:\, E:\...)
def get_connected_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            drive = f"{chr(65 + i)}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    return set(drives)

# ✅ Main Logic
def monitor_usb():
    print("🔐 USB Physical Security Started...")
    prev_drives = get_connected_drives()

    while True:
        time.sleep(2)
        current_drives = get_connected_drives()
        new_drives = current_drives - prev_drives

        if new_drives:
            print(f"🔌 USB detected: {new_drives}")
            try:
                password = getpass.getpass("Enter password to allow USB access: ")
            except Exception:
                password = input("Enter password (visible): ")

            if password != "admin123":  # Change this password if needed
                print("❌ Wrong password. Blocking USB access...")
                disable_usb()
            else:
                print("✅ Access granted. USB remains enabled.")
                enable_usb()
            break

# ✅ Run only if Admin
if __name__ == "__main__":
    if not is_admin():
        print("⚠️ Please run this script as Administrator!")
        exit()
    monitor_usb()
