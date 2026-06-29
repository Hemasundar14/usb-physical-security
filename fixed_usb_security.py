import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import time
import os
import ctypes
import winreg
import sys
import json
import datetime
import sqlite3
import hashlib
import base64

class FixedUSBSecurity:
    def __init__(self):
        self.config_file = "fixed_config.json"
        self.db_file = "security_audit.db"
        self.setup_database()
        self.load_config()
    
    def setup_database(self):
        """Setup SQLite database for audit logging"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                user TEXT,
                details TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE,
                device_name TEXT,
                added_date TEXT,
                added_by TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def log_event(self, action, details=""):
        """Log security events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().isoformat()
        user = os.getenv('USERNAME', 'Unknown')
        
        cursor.execute('''
            INSERT INTO audit_log (timestamp, action, user, details)
            VALUES (?, ?, ?, ?)
        ''', (timestamp, action, user, details))
        conn.commit()
        conn.close()
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def load_config(self):
        """Load configuration"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                "admin_password": self.hash_password("admin123"),
                "auto_block": True,
                "audit_logging": True,
                "session_timeout": 30,
                "whitelist_enabled": False
            }
            self.save_config()
    
    def save_config(self):
        """Save configuration"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def verify_password(self, password):
        """Verify password"""
        return self.hash_password(password) == self.config["admin_password"]

class FixedUSBSecurityApp:
    def __init__(self, root):
        self.root = root
        self.security = FixedUSBSecurity()
        self.setup_ui()
        self.usb_enabled = True
        self.is_processing = False
        self.session_start = time.time()
        self.monitoring = True
        
        # Start monitoring
        threading.Thread(target=self.monitor_usb, daemon=True).start()
        threading.Thread(target=self.session_monitor, daemon=True).start()
    
    def setup_ui(self):
        """Setup enhanced user interface"""
        self.root.title("Fixed USB Physical Security v2.0")
        self.root.geometry("800x600")
        self.root.configure(bg="#2d2d2d")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Main Control Tab
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text="🔒 Main Control")
        self.setup_main_control()
        
        # Settings Tab
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        self.setup_settings()
        
        # Audit Log Tab
        self.audit_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.audit_frame, text="📋 Audit Log")
        self.setup_audit_log()
        
        # Whitelist Tab
        self.whitelist_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.whitelist_frame, text="✅ Device Whitelist")
        self.setup_whitelist()
    
    def setup_main_control(self):
        """Setup main control interface"""
        # Title
        title_label = tk.Label(self.main_frame, text="Fixed USB Physical Security v2.0", 
                              font=("Arial", 18, "bold"), fg="#00ff00", bg="#2d2d2d")
        title_label.pack(pady=20)
        
        # Status frame
        status_frame = tk.Frame(self.main_frame, bg="#2d2d2d")
        status_frame.pack(pady=20)
        
        self.status_label = tk.Label(status_frame, text="USB Status: ENABLED", 
                                    font=("Arial", 14, "bold"), fg="#00ff00", bg="#2d2d2d")
        self.status_label.pack()
        
        self.process_label = tk.Label(status_frame, text="", 
                                     font=("Arial", 10), fg="#ffffff", bg="#2d2d2d")
        self.process_label.pack()
        
        # Control buttons
        button_frame = tk.Frame(self.main_frame, bg="#2d2d2d")
        button_frame.pack(pady=30)
        
        self.disable_button = tk.Button(button_frame, text="🔒 Disable USB", 
                                       font=("Arial", 12, "bold"), bg="#ff4444", fg="white",
                                       width=20, command=self.disable_usb)
        self.disable_button.pack(pady=10)
        
        self.enable_button = tk.Button(button_frame, text="🔓 Enable USB", 
                                      font=("Arial", 12, "bold"), bg="#44ff44", fg="white",
                                      width=20, command=self.enable_usb)
        self.enable_button.pack(pady=10)
        
        # Quick actions
        quick_frame = tk.Frame(self.main_frame, bg="#2d2d2d")
        quick_frame.pack(pady=20)
        
        tk.Button(quick_frame, text="📊 System Info", 
                 font=("Arial", 10), bg="#4444ff", fg="white",
                 command=self.show_system_info).pack(side=tk.LEFT, padx=5)
        
        tk.Button(quick_frame, text="🔍 Scan USB", 
                 font=("Arial", 10), bg="#ff8844", fg="white",
                 command=self.scan_usb_devices).pack(side=tk.LEFT, padx=5)
    
    def setup_settings(self):
        """Setup settings interface"""
        # Password management
        pwd_frame = tk.LabelFrame(self.settings_frame, text="🔐 Password Management", 
                                 font=("Arial", 12, "bold"), fg="#00ff00")
        pwd_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Button(pwd_frame, text="Change Admin Password", 
                 command=self.change_password).pack(pady=10)
        
        # Security settings
        sec_frame = tk.LabelFrame(self.settings_frame, text="🛡️ Security Settings", 
                                 font=("Arial", 12, "bold"), fg="#00ff00")
        sec_frame.pack(fill='x', padx=20, pady=10)
        
        self.auto_block_var = tk.BooleanVar(value=self.security.config["auto_block"])
        tk.Checkbutton(sec_frame, text="Auto-block unauthorized USB devices", 
                      variable=self.auto_block_var, command=self.save_settings).pack()
        
        self.whitelist_var = tk.BooleanVar(value=self.security.config["whitelist_enabled"])
        tk.Checkbutton(sec_frame, text="Enable device whitelist", 
                      variable=self.whitelist_var, command=self.save_settings).pack()
        
        self.audit_var = tk.BooleanVar(value=self.security.config["audit_logging"])
        tk.Checkbutton(sec_frame, text="Enable audit logging", 
                      variable=self.audit_var, command=self.save_settings).pack()
        
        # Session timeout
        timeout_frame = tk.Frame(sec_frame)
        timeout_frame.pack(pady=10)
        tk.Label(timeout_frame, text="Session Timeout (minutes):").pack(side=tk.LEFT)
        self.timeout_entry = tk.Entry(timeout_frame, width=10)
        self.timeout_entry.insert(0, str(self.security.config["session_timeout"]))
        self.timeout_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(timeout_frame, text="Save", command=self.save_settings).pack(side=tk.LEFT)
    
    def setup_audit_log(self):
        """Setup audit log interface"""
        # Create treeview for audit log
        columns = ("Timestamp", "Action", "User", "Details")
        self.audit_tree = ttk.Treeview(self.audit_frame, columns=columns, show='headings')
        
        for col in columns:
            self.audit_tree.heading(col, text=col)
            self.audit_tree.column(col, width=150)
        
        self.audit_tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Refresh button
        tk.Button(self.audit_frame, text="🔄 Refresh Log", 
                 command=self.refresh_audit_log).pack(pady=10)
        
        self.refresh_audit_log()
    
    def setup_whitelist(self):
        """Setup device whitelist interface"""
        # Add device frame
        add_frame = tk.LabelFrame(self.whitelist_frame, text="➕ Add Device to Whitelist", 
                                 font=("Arial", 12, "bold"), fg="#00ff00")
        add_frame.pack(fill='x', padx=20, pady=10)
        
        tk.Button(add_frame, text="Scan and Add Current USB Device", 
                 command=self.add_current_device).pack(pady=10)
        
        # Whitelist treeview
        columns = ("Device ID", "Device Name", "Added Date", "Added By")
        self.whitelist_tree = ttk.Treeview(self.whitelist_frame, columns=columns, show='headings')
        
        for col in columns:
            self.whitelist_tree.heading(col, text=col)
            self.whitelist_tree.column(col, width=150)
        
        self.whitelist_tree.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Remove button
        tk.Button(self.whitelist_frame, text="❌ Remove Selected Device", 
                 command=self.remove_whitelist_device).pack(pady=10)
        
        self.refresh_whitelist()
    
    def change_password(self):
        """Change admin password"""
        current = simpledialog.askstring("Change Password", "Enter current password:", show='*')
        if not current or not self.security.verify_password(current):
            messagebox.showerror("Error", "Incorrect current password")
            return
        
        new_password = simpledialog.askstring("Change Password", "Enter new password:", show='*')
        if new_password:
            confirm_password = simpledialog.askstring("Change Password", "Confirm new password:", show='*')
            if new_password == confirm_password:
                self.security.config["admin_password"] = self.security.hash_password(new_password)
                self.security.save_config()
                self.security.log_event("Password Changed", "Admin password updated")
                messagebox.showinfo("Success", "Password changed successfully")
            else:
                messagebox.showerror("Error", "Passwords do not match")
    
    def save_settings(self):
        """Save settings"""
        self.security.config["auto_block"] = self.auto_block_var.get()
        self.security.config["whitelist_enabled"] = self.whitelist_var.get()
        self.security.config["audit_logging"] = self.audit_var.get()
        
        try:
            timeout = int(self.timeout_entry.get())
            self.security.config["session_timeout"] = timeout
        except ValueError:
            messagebox.showerror("Error", "Invalid timeout value")
            return
        
        self.security.save_config()
        self.security.log_event("Settings Updated", "Security settings modified")
        messagebox.showinfo("Success", "Settings saved successfully")
    
    def refresh_audit_log(self):
        """Refresh audit log display"""
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        
        conn = sqlite3.connect(self.security.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, action, user, details FROM audit_log ORDER BY timestamp DESC LIMIT 50')
        
        for row in cursor.fetchall():
            self.audit_tree.insert('', 'end', values=row)
        
        conn.close()
    
    def refresh_whitelist(self):
        """Refresh whitelist display"""
        for item in self.whitelist_tree.get_children():
            self.whitelist_tree.delete(item)
        
        conn = sqlite3.connect(self.security.db_file)
        cursor = conn.cursor()
        cursor.execute('SELECT device_id, device_name, added_date, added_by FROM whitelist')
        
        for row in cursor.fetchall():
            self.whitelist_tree.insert('', 'end', values=row)
        
        conn.close()
    
    def add_current_device(self):
        """Add current USB device to whitelist"""
        device_id = f"USB_{int(time.time())}"
        device_name = "Unknown Device"
        
        conn = sqlite3.connect(self.security.db_file)
        cursor = conn.cursor()
        cursor.execute('INSERT OR REPLACE INTO whitelist (device_id, device_name, added_date, added_by) VALUES (?, ?, ?, ?)',
                      (device_id, device_name, datetime.datetime.now().isoformat(), os.getenv('USERNAME', 'Unknown')))
        conn.commit()
        conn.close()
        
        self.security.log_event("Device Whitelisted", f"Added device: {device_id}")
        self.refresh_whitelist()
        messagebox.showinfo("Success", "Device added to whitelist")
    
    def remove_whitelist_device(self):
        """Remove device from whitelist"""
        selection = self.whitelist_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a device to remove")
            return
        
        item = self.whitelist_tree.item(selection[0])
        device_id = item['values'][0]
        
        conn = sqlite3.connect(self.security.db_file)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM whitelist WHERE device_id = ?', (device_id,))
        conn.commit()
        conn.close()
        
        self.security.log_event("Device Removed from Whitelist", f"Removed device: {device_id}")
        self.refresh_whitelist()
        messagebox.showinfo("Success", "Device removed from whitelist")
    
    def show_system_info(self):
        """Show system information"""
        info = f"""
System Information:
- OS: {os.name}
- Platform: {sys.platform}
- Python Version: {sys.version}
- Current User: {os.getenv('USERNAME', 'Unknown')}
- Computer Name: {os.getenv('COMPUTERNAME', 'Unknown')}
- Admin Rights: {'Yes' if self.is_admin() else 'No'}
        """
        messagebox.showinfo("System Information", info)
    
    def scan_usb_devices(self):
        """Scan for USB devices"""
        drives = self.get_connected_drives()
        if drives:
            device_list = "\n".join(drives)
            messagebox.showinfo("USB Devices Found", f"Connected USB devices:\n{device_list}")
        else:
            messagebox.showinfo("USB Devices", "No USB storage devices found")
    
    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def get_connected_drives(self):
        """Get list of connected drives"""
        drives = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drive = f"{chr(65 + i)}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        return set(drives)
    
    def disable_usb_ports(self):
        """Disable USB storage ports"""
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 4)
            winreg.CloseKey(reg_key)
            if self.security.config["audit_logging"]:
                self.security.log_event("USB Disabled", "USB storage ports disabled")
            return True
        except Exception as e:
            if self.security.config["audit_logging"]:
                self.security.log_event("USB Disable Failed", str(e))
            return False
    
    def enable_usb_ports(self):
        """Enable USB storage ports"""
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 3)
            winreg.CloseKey(reg_key)
            if self.security.config["audit_logging"]:
                self.security.log_event("USB Enabled", "USB storage ports enabled")
            return True
        except Exception as e:
            if self.security.config["audit_logging"]:
                self.security.log_event("USB Enable Failed", str(e))
            return False
    
    def update_ui(self):
        """Update user interface"""
        status = "ENABLED" if self.usb_enabled else "DISABLED"
        color = "#00ff00" if self.usb_enabled else "#ff4444"
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
        """Simulate USB action with processing delay"""
        self.is_processing = True
        self.update_ui()
        time.sleep(1.5)
        
        if enable:
            success = self.enable_usb_ports()
        else:
            success = self.disable_usb_ports()
        
        if success:
            self.usb_enabled = enable
        else:
            messagebox.showerror("Error", f"Failed to {'enable' if enable else 'disable'} USB ports")
        
        self.is_processing = False
        self.update_ui()
    
    def disable_usb(self):
        """Disable USB ports"""
        threading.Thread(target=self.simulate_action, args=(False,), daemon=True).start()
    
    def enable_usb(self):
        """Enable USB ports with authentication"""
        if not self.authenticate_user():
            return
        
        threading.Thread(target=self.simulate_action, args=(True,), daemon=True).start()
    
    def authenticate_user(self):
        """Authenticate user before enabling USB"""
        password = simpledialog.askstring("Authentication", "Enter admin password:", show='*')
        if not password:
            return False
        
        if not self.security.verify_password(password):
            messagebox.showerror("Access Denied", "Incorrect password")
            if self.security.config["audit_logging"]:
                self.security.log_event("Authentication Failed", "Incorrect password entered")
            return False
        
        if self.security.config["audit_logging"]:
            self.security.log_event("Authentication Success", "Correct password entered")
        return True
    
    def monitor_usb(self):
        """Monitor USB devices in background"""
        prev_drives = self.get_connected_drives()
        while self.monitoring:
            time.sleep(2)
            current_drives = self.get_connected_drives()
            new_drives = current_drives - prev_drives
            
            if new_drives and self.security.config["auto_block"]:
                self.root.after(0, self.handle_new_device, new_drives)
            
            prev_drives = current_drives
    
    def handle_new_device(self, new_drives):
        """Handle newly connected USB devices"""
        device_list = ", ".join(new_drives)
        if self.security.config["audit_logging"]:
            self.security.log_event("USB Device Detected", f"New devices: {device_list}")
        
        if self.security.config["whitelist_enabled"]:
            # Check if device is in whitelist
            if not self.is_device_whitelisted(new_drives):
                messagebox.showwarning("Unauthorized Device", 
                                     f"Unauthorized USB device detected: {device_list}\nDevice has been blocked.")
                self.disable_usb_ports()
                self.usb_enabled = False
                self.update_ui()
        else:
            # Ask for password
            if not self.authenticate_user():
                self.disable_usb_ports()
                self.usb_enabled = False
                self.update_ui()
    
    def is_device_whitelisted(self, drives):
        """Check if device is in whitelist"""
        # Simplified implementation - in real scenario, you'd check device IDs
        return False
    
    def session_monitor(self):
        """Monitor session timeout"""
        while self.monitoring:
            time.sleep(60)  # Check every minute
            elapsed = (time.time() - self.session_start) / 60
            timeout = self.security.config["session_timeout"]
            
            if elapsed > timeout:
                self.root.after(0, self.session_timeout)
                break
    
    def session_timeout(self):
        """Handle session timeout"""
        messagebox.showwarning("Session Timeout", "Session has expired. Please restart the application.")
        self.monitoring = False
        self.root.quit()

def main():
    """Main application entry point"""
    if not is_admin():
        messagebox.showwarning("Permission Denied", "Please run the app as Administrator!")
        sys.exit()
    
    root = tk.Tk()
    app = FixedUSBSecurityApp(root)
    
    def on_closing():
        app.monitoring = False
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

def is_admin():
    """Check if running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    main()
