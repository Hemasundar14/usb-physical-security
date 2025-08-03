import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import time
import os
import ctypes
import winreg
import webbrowser
import base64
import sys

# ✅ Registry Functions
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def disable_usb_ports():
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 4)
        winreg.CloseKey(reg_key)
        print("🔒 USB ports disabled.")
    except Exception as e:
        print(f"Error disabling USB: {e}")

def enable_usb_ports():
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 3)
        winreg.CloseKey(reg_key)
        print("🔓 USB ports enabled.")
    except Exception as e:
        print(f"Error enabling USB: {e}")

def get_connected_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for i in range(26):
        if bitmask & (1 << i):
            drive = f"{chr(65 + i)}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    return set(drives)

# ✅ GUI App
class USBPhysicalSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Physical Security For Systems")
        self.root.geometry("420x480")
        self.root.configure(bg="black")

        self.usb_enabled = True
        self.is_processing = False

        self.info_button = tk.Button(root, text="Project Info", bg="red", fg="white",
                                     font=("Helvetica", 12, "bold"), command=self.show_info)
        self.info_button.pack(pady=(10, 5))

        self.title_label = tk.Label(root, text="USB Physical Security!!!", font=("Helvetica", 16, "bold"),
                                    fg="white", bg="black")
        self.title_label.pack(pady=10)

        self.status_label = tk.Label(root, text="USB Status: ENABLED", font=("Helvetica", 14),
                                     fg="lime", bg="black")
        self.status_label.pack(pady=5)

        self.process_label = tk.Label(root, text="", font=("Helvetica", 11),
                                      fg="white", bg="black")
        self.process_label.pack(pady=2)

        self.button_frame = tk.Frame(root, bg="black")
        self.button_frame.pack(pady=20)

        self.disable_button = tk.Button(self.button_frame, text="Disable USB", bg="red", fg="white",
                                        font=("Helvetica", 12), width=20, command=self.disable_usb)
        self.disable_button.pack(pady=10)

        self.enable_button = tk.Button(self.button_frame, text="Enable USB", bg="green", fg="white",
                                       font=("Helvetica", 12), width=20, command=self.enable_usb, state="disabled")
        self.enable_button.pack(pady=10)

        threading.Thread(target=self.monitor_usb, daemon=True).start()

    def show_info(self):
        html_path = os.path.join(os.getcwd(), "project_info.html")
        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>USB Physical Security - Project Info</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f2f2f2;
      margin: 40px;
    }
    .container {
      background: white;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 0 15px rgba(0,0,0,0.2);
      position: relative;
    }
    .logo {
      position: absolute;
      top: 20px;
      right: 20px;
      height: 60px;
    }
    h2 {
      margin-top: 0;
      font-size: 26px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    th, td {
      border: 1px solid #555;
      padding: 10px;
      text-align: left;
    }
    th {
      background-color: #ddd;
    }
    .section-title {
      margin-top: 30px;
      font-size: 20px;
      font-weight: bold;
      border-bottom: 2px solid #333;
      padding-bottom: 5px;
    }
  </style>
</head>
<body>
  <div class="container">
      <img src="images.png" alt="Logo" class="logo">
    </a>

    <h2>Project Information</h2>
    <p>
      This project was developed by <strong>R.Hemasundar</strong> and <strong>Manohar</strong> as part of a <strong>Cyber Security Internship</strong>.<br>
      The project aims to <strong>secure organizations from cyber frauds performed by hackers</strong> using physical USB security.
    </p>

    <div class="section-title">Project Details</div>
    <table>
      <tr><th>Project Name</th><td>USB PHYSICAL SECURITY</td></tr>
      <tr><th>Project Description</th><td>Implementing physical security policy on USB ports in organization for physical security.</td></tr>
      <tr><th>Project Start Date</th><td>12-July-2025</td></tr>
      <tr><th>Project End Date</th><td>14-August-2025</td></tr>
      <tr><th>Project Status</th><td>Completed</td></tr>
    </table>

    <div class="section-title">Developer Details</div>
    <table>
      <tr>
        <th>Name</th>
        <th>Employee ID</th>
        <th>Email</th>
      </tr>
      <tr>
        <td>Hemasundar</td>
        <td>ST#IS#7525</td>
        <td>sundarstark14@gmail.com</td>
      </tr>
      <tr>
        <td>Manohar</td>
        <td>ST#IS#7561</td>
        <td>manoharmuttamala@gmail.com</td>
      </tr>
    </table>

    <div class="section-title">Company Details</div>
    <table>
      <tr><th>Company</th><th>Value</th></tr>
      <tr><td>Name</td><td>Supraja Technologies</td></tr>
      <tr><td>Email</td><td>contact@suprajatechnologies.com</td></tr>
    </table>
  </div>
</body>
</html>
"""
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        webbrowser.open(f"file://{html_path}")

    def update_ui(self):
        status = "ENABLED" if self.usb_enabled else "DISABLED"
        color = "lime" if self.usb_enabled else "red"
        self.status_label.config(text=f"USB Status: {status}", fg=color)

        if self.is_processing:
            self.process_label.config(text="Applying changes...")
            self.disable_button.config(state="disabled")
            self.enable_button.config(state="disabled")
        else:
            self.process_label.config(text="")
            self.disable_button.config(state="normal" if self.usb_enabled else "disabled")
            self.enable_button.config(state="normal" if not self.usb_enabled else "disabled")

    def simulate_action(self, enable: bool):
        self.is_processing = True
        self.update_ui()
        time.sleep(1.5)
        if enable:
            enable_usb_ports()
        else:
            disable_usb_ports()
        self.usb_enabled = enable
        self.is_processing = False
        self.update_ui()

    def disable_usb(self):
        threading.Thread(target=self.simulate_action, args=(False,), daemon=True).start()

    def enable_usb(self):
        def check_password():
            entered = password_entry.get()
            if entered == "admin123":
                messagebox.showinfo("Access Granted", "Correct password. USB will be enabled.")
                enable_usb_ports()
                self.usb_enabled = True
                self.update_ui()
                password_window.destroy()
                encoded = base64.b64encode(entered.encode()).decode()
                messagebox.showinfo("Encoded Password", f"Base64 Encoded: {encoded}")
            else:
                messagebox.showwarning("Access Denied", "Incorrect password.")
                disable_usb_ports()
                self.usb_enabled = False
                self.update_ui()
                password_window.destroy()

        password_window = tk.Toplevel(self.root)
        password_window.title("Authentication Required")
        password_window.geometry("300x200")
        password_window.configure(bg="black")
        password_window.grab_set()

        label = tk.Label(password_window, text="Enter Password", font=("Helvetica", 12, "bold"),
                         fg="white", bg="black")
        label.pack(pady=(30, 10))

        password_entry = tk.Entry(password_window, show="*", font=("Helvetica", 12), width=25)
        password_entry.pack(pady=5)
        password_entry.focus()

        submit_button = tk.Button(password_window, text="Submit", font=("Helvetica", 11),
                                  bg="green", fg="white", command=check_password)
        submit_button.pack(pady=20)

    def monitor_usb(self):
        prev_drives = get_connected_drives()
        while True:
            time.sleep(2)
            current_drives = get_connected_drives()
            new_drives = current_drives - prev_drives
            if new_drives:
                password = simpledialog.askstring("USB Access", "Enter password to allow USB:", show='*')
                if password != "admin123":
                    messagebox.showwarning("Access Denied", "Wrong password. Blocking USB access.")
                    disable_usb_ports()
                    self.usb_enabled = False
                else:
                    messagebox.showinfo("Access Granted", "Correct password. USB remains enabled.")
                    enable_usb_ports()
                    self.usb_enabled = True
                self.update_ui()
            prev_drives = current_drives

# ✅ Run App
if __name__ == "__main__":
    if not is_admin():
        messagebox.showwarning("Permission Denied", "Please run the app as Administrator!")
        sys.exit()

    root = tk.Tk()
    app = USBPhysicalSecurityApp(root)
    root.mainloop()
