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
import re
from contextlib import contextmanager

class ImprovedUSBSecurity:
    def __init__(self):
        self.config_file = "improved_config.json"
        self.db_file = "security_audit.db"
        self.setup_database()
        self.load_config()
    
    @contextmanager
    def get_db_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def setup_database(self):
        """Setup SQLite database for audit logging"""
        try:
            with self.get_db_connection() as conn:
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
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS login_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        user TEXT,
                        success BOOLEAN
                    )
                ''')
                conn.commit()
        except Exception as e:
            messagebox.showerror("Database Error", f"Failed to setup database: {e}")
    
    def log_event(self, action, details=""):
        """Log security events with error handling"""
        try:
            with self.get_db_connection() as conn:
                cursor = conn.cursor()
                timestamp = datetime.datetime.now().isoformat()
                user = os.getenv('USERNAME', 'Unknown')
                
                cursor.execute('''
                    INSERT INTO audit_log (timestamp, action, user, details)
                    VALUES (?, ?, ?, ?)
                ''', (timestamp, action, user, details))
                conn.commit()
        except Exception as e:
            print(f"Failed to log event: {e}")
    
    def log_login_attempt(self, success):
        """Log login attempts for security monitoring"""
        try:
            with self.get_db_connection() as conn:
                cursor = conn.cursor()
                timestamp = datetime.datetime.now().isoformat()
                user = os.getenv('USERNAME', 'Unknown')
                
                cursor.execute('''
                    INSERT INTO login_attempts (timestamp, user, success)
                    VALUES (?, ?, ?)
                ''', (timestamp, user, success))
                conn.commit()
        except Exception as e:
            print(f"Failed to log login attempt: {e}")
    
    def hash_password(self, password):
        """Hash password using SHA-256 with salt"""
        salt = "USB_SECURITY_SALT_2024"
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def validate_password_strength(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        
        return True, "Password is strong"
    
    def load_config(self):
        """Load configuration with error handling"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = {
                    "admin_password": self.hash_password("Admin123!"),
                    "auto_block": True,
                    "audit_logging": True,
                    "session_timeout": 30,
                    "whitelist_enabled": False,
                    "max_login_attempts": 3,
                    "lockout_duration": 15
                }
                self.save_config()
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to load configuration: {e}")
            self.config = {}
    
    def save_config(self):
        """Save configuration with error handling"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to save configuration: {e}")
    
    def verify_password(self, password):
        """Verify password with login attempt tracking"""
        hashed_input = self.hash_password(password)
        is_valid = hashed_input == self.config.get("admin_password", "")
        
        # Log login attempt
        self.log_login_attempt(is_valid)
        
        # Check for too many failed attempts
        failed_attempts = self.get_recent_failed_attempts()
        if failed_attempts >= self.config.get("max_login_attempts", 3):
            lockout_duration = self.config.get("lockout_duration", 15)
            messagebox.showerror("Account Locked", 
                               f"Too many failed attempts. Account locked for {lockout_duration} minutes.")
            return False
        
        return is_valid
    
    def get_recent_failed_attempts(self):
        """Get number of recent failed login attempts"""
        try:
            with self.get_db_connection() as conn:
                cursor = conn.cursor()
                # Check attempts in the last 15 minutes
                cutoff_time = (datetime.datetime.now() - datetime.timedelta(minutes=15)).isoformat()
                cursor.execute('''
                    SELECT COUNT(*) FROM login_attempts 
                    WHERE success = 0 AND timestamp > ?
                ''', (cutoff_time,))
                return cursor.fetchone()[0]
        except Exception as e:
            print(f"Failed to get failed attempts: {e}")
            return 0

class ImprovedUSBSecurityApp:
    def __init__(self, root):
        self.root = root
        self.security = ImprovedUSBSecurity()
        self.setup_ui()
        self.usb_enabled = True
        self.is_processing = False
        self.session_start = time.time()
        self.monitoring = True
        self.last_activity = time.time()
        
        # Start monitoring threads
        threading.Thread(target=self.monitor_usb, daemon=True).start()
        threading.Thread(target=self.session_monitor, daemon=True).start()
    
    def setup_ui(self):
        """Setup enhanced user interface"""
        self.root.title("Improved USB Physical Security v2.1")
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
        
        # Security Tab
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="🛡️ Security")
        self.setup_security()
    
    def setup_main_control(self):
        """Setup main control interface"""
        # Title
        title_label = tk.Label(self.main_frame, text="Improved USB Physical Security v2.1", 
                              font=("Arial", 18, "bold"), fg="#00ff00", bg="#1e1e1e")
        title_label.pack(pady=20)
        
        # Status frame
        status_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        status_frame.pack(pady=20)
        
        self.status_label = tk.Label(status_frame, text="USB Status: ENABLED", 
                                    font=("Arial", 14, "bold"), fg="#00ff00", bg="#1e1e1e")
        self.status_label.pack()
        
        self.process_label = tk.Label(status_frame, text="", 
                                     font=("Arial", 10), fg="#ffffff", bg="#1e1e1e")
        self.process_label.pack()
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress_bar.pack(pady=5)
        
        # Control buttons
        button_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
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
        quick_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
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
        
        self.auto_block_var = tk.BooleanVar(value=self.security.config.get("auto_block", True))
        tk.Checkbutton(sec_frame, text="Auto-block unauthorized USB devices", 
                      variable=self.auto_block_var, command=self.save_settings).pack()
        
        self.audit_var = tk.BooleanVar(value=self.security.config.get("audit_logging", True))
        tk.Checkbutton(sec_frame, text="Enable audit logging", 
                      variable=self.audit_var, command=self.save_settings).pack()
        
        # Session timeout
        timeout_frame = tk.Frame(sec_frame)
        timeout_frame.pack(pady=10)
        tk.Label(timeout_frame, text="Session Timeout (minutes):").pack(side=tk.LEFT)
        self.timeout_entry = tk.Entry(timeout_frame, width=10)
        self.timeout_entry.insert(0, str(self.security.config.get("session_timeout", 30)))
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
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.audit_frame, orient="vertical", command=self.audit_tree.yview)
        self.audit_tree.configure(yscrollcommand=scrollbar.set)
        
        self.audit_tree.pack(side="left", fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")
        
        # Refresh button
        tk.Button(self.audit_frame, text="🔄 Refresh Log", 
                 command=self.refresh_audit_log).pack(pady=10)
        
        self.refresh_audit_log()
    
    def setup_security(self):
        """Setup security monitoring interface"""
        # Login attempts frame
        login_frame = tk.LabelFrame(self.security_frame, text="🔐 Login Attempts", 
                                   font=("Arial", 12, "bold"), fg="#00ff00")
        login_frame.pack(fill='x', padx=20, pady=10)
        
        self.login_attempts_label = tk.Label(login_frame, text="Recent failed attempts: 0", 
                                           font=("Arial", 10), fg="#ffffff", bg="#1e1e1e")
        self.login_attempts_label.pack(pady=10)
        
        # Security settings
        sec_settings_frame = tk.LabelFrame(self.security_frame, text="⚙️ Security Settings", 
                                          font=("Arial", 12, "bold"), fg="#00ff00")
        sec_settings_frame.pack(fill='x', padx=20, pady=10)
        
        # Max login attempts
        attempts_frame = tk.Frame(sec_settings_frame)
        attempts_frame.pack(pady=5)
        tk.Label(attempts_frame, text="Max Login Attempts:").pack(side=tk.LEFT)
        self.max_attempts_entry = tk.Entry(attempts_frame, width=10)
        self.max_attempts_entry.insert(0, str(self.security.config.get("max_login_attempts", 3)))
        self.max_attempts_entry.pack(side=tk.LEFT, padx=5)
        
        # Lockout duration
        lockout_frame = tk.Frame(sec_settings_frame)
        lockout_frame.pack(pady=5)
        tk.Label(lockout_frame, text="Lockout Duration (minutes):").pack(side=tk.LEFT)
        self.lockout_entry = tk.Entry(lockout_frame, width=10)
        self.lockout_entry.insert(0, str(self.security.config.get("lockout_duration", 15)))
        self.lockout_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Button(sec_settings_frame, text="Save Security Settings", 
                 command=self.save_security_settings).pack(pady=10)
        
        # Update login attempts display
        self.update_login_attempts_display()
    
    def update_login_attempts_display(self):
        """Update the login attempts display"""
        try:
            failed_attempts = self.security.get_recent_failed_attempts()
            self.login_attempts_label.config(text=f"Recent failed attempts: {failed_attempts}")
            # Update every 30 seconds
            self.root.after(30000, self.update_login_attempts_display)
        except Exception as e:
            print(f"Error updating login attempts display: {e}")
    
    def change_password(self):
        """Change admin password with strength validation"""
        current = simpledialog.askstring("Change Password", "Enter current password:", show='*')
        if not current or not self.security.verify_password(current):
            messagebox.showerror("Error", "Incorrect current password")
            return
        
        new_password = simpledialog.askstring("Change Password", "Enter new password:", show='*')
        if new_password:
            # Validate password strength
            is_strong, message = self.security.validate_password_strength(new_password)
            if not is_strong:
                messagebox.showerror("Weak Password", message)
                return
            
            confirm_password = simpledialog.askstring("Change Password", "Confirm new password:", show='*')
            if new_password == confirm_password:
                self.security.config["admin_password"] = self.security.hash_password(new_password)
                self.security.save_config()
                self.security.log_event("Password Changed", "Admin password updated")
                messagebox.showinfo("Success", "Password changed successfully")
            else:
                messagebox.showerror("Error", "Passwords do not match")
    
    def save_settings(self):
        """Save settings with validation"""
        try:
            self.security.config["auto_block"] = self.auto_block_var.get()
            self.security.config["audit_logging"] = self.audit_var.get()
            
            timeout = int(self.timeout_entry.get())
            if timeout < 1 or timeout > 480:  # 1 minute to 8 hours
                messagebox.showerror("Error", "Session timeout must be between 1 and 480 minutes")
                return
            
            self.security.config["session_timeout"] = timeout
            self.security.save_config()
            self.security.log_event("Settings Updated", "Security settings modified")
            messagebox.showinfo("Success", "Settings saved successfully")
        except ValueError:
            messagebox.showerror("Error", "Invalid timeout value")
    
    def save_security_settings(self):
        """Save security-specific settings"""
        try:
            max_attempts = int(self.max_attempts_entry.get())
            lockout_duration = int(self.lockout_entry.get())
            
            if max_attempts < 1 or max_attempts > 10:
                messagebox.showerror("Error", "Max login attempts must be between 1 and 10")
                return
            
            if lockout_duration < 1 or lockout_duration > 60:
                messagebox.showerror("Error", "Lockout duration must be between 1 and 60 minutes")
                return
            
            self.security.config["max_login_attempts"] = max_attempts
            self.security.config["lockout_duration"] = lockout_duration
            self.security.save_config()
            self.security.log_event("Security Settings Updated", "Login security settings modified")
            messagebox.showinfo("Success", "Security settings saved successfully")
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values")
    
    def refresh_audit_log(self):
        """Refresh audit log display"""
        try:
            for item in self.audit_tree.get_children():
                self.audit_tree.delete(item)
            
            with self.security.get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT timestamp, action, user, details 
                    FROM audit_log 
                    ORDER BY timestamp DESC 
                    LIMIT 100
                ''')
                
                for row in cursor.fetchall():
                    self.audit_tree.insert('', 'end', values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh audit log: {e}")
    
    def show_system_info(self):
        """Show detailed system information"""
        info = f"""
System Information:
- OS: {os.name}
- Platform: {sys.platform}
- Python Version: {sys.version}
- Current User: {os.getenv('USERNAME', 'Unknown')}
- Computer Name: {os.getenv('COMPUTERNAME', 'Unknown')}
- Admin Rights: {'Yes' if self.is_admin() else 'No'}
- Application Version: 2.1
- Database File: {self.security.db_file}
- Config File: {self.security.config_file}
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
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    drive = f"{chr(65 + i)}:\\"
                    if os.path.exists(drive):
                        drives.append(drive)
        except Exception as e:
            print(f"Error getting drives: {e}")
        return set(drives)
    
    def disable_usb_ports(self):
        """Disable USB storage ports with error handling"""
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 4)
            winreg.CloseKey(reg_key)
            
            if self.security.config.get("audit_logging", True):
                self.security.log_event("USB Disabled", "USB storage ports disabled")
            return True
        except Exception as e:
            if self.security.config.get("audit_logging", True):
                self.security.log_event("USB Disable Failed", str(e))
            return False
    
    def enable_usb_ports(self):
        """Enable USB storage ports with error handling"""
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                     r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(reg_key, "Start", 0, winreg.REG_DWORD, 3)
            winreg.CloseKey(reg_key)
            
            if self.security.config.get("audit_logging", True):
                self.security.log_event("USB Enabled", "USB storage ports enabled")
            return True
        except Exception as e:
            if self.security.config.get("audit_logging", True):
                self.security.log_event("USB Enable Failed", str(e))
            return False
    
    def update_ui(self):
        """Update user interface with thread safety"""
        try:
            status = "ENABLED" if self.usb_enabled else "DISABLED"
            color = "#00ff00" if self.usb_enabled else "#ff4444"
            self.status_label.config(text=f"USB Status: {status}", fg=color)
            
            if self.is_processing:
                self.process_label.config(text="Applying changes...")
                self.progress_bar.start()
                self.disable_button.config(state="disabled")
                self.enable_button.config(state="disabled")
            else:
                self.process_label.config(text="")
                self.progress_bar.stop()
                self.disable_button.config(state="normal" if self.usb_enabled else "disabled")
                self.enable_button.config(state="normal" if not self.usb_enabled else "disabled")
        except Exception as e:
            print(f"Error updating UI: {e}")
    
    def simulate_action(self, enable: bool):
        """Simulate USB action with processing delay and progress feedback"""
        try:
            self.is_processing = True
            self.root.after(0, self.update_ui)
            time.sleep(1.5)
            
            if enable:
                success = self.enable_usb_ports()
            else:
                success = self.disable_usb_ports()
            
            if success:
                self.usb_enabled = enable
            else:
                self.root.after(0, lambda: messagebox.showerror("Error", 
                    f"Failed to {'enable' if enable else 'disable'} USB ports"))
            
            self.is_processing = False
            self.root.after(0, self.update_ui)
        except Exception as e:
            self.is_processing = False
            self.root.after(0, lambda: messagebox.showerror("Error", f"Action failed: {e}"))
            self.root.after(0, self.update_ui)
    
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
            return False
        
        return True
    
    def monitor_usb(self):
        """Monitor USB devices in background"""
        prev_drives = self.get_connected_drives()
        while self.monitoring:
            try:
                time.sleep(2)
                current_drives = self.get_connected_drives()
                new_drives = current_drives - prev_drives
                
                if new_drives and self.security.config.get("auto_block", True):
                    self.root.after(0, self.handle_new_device, new_drives)
                
                prev_drives = current_drives
            except Exception as e:
                print(f"Error in USB monitoring: {e}")
    
    def handle_new_device(self, new_drives):
        """Handle newly connected USB devices"""
        try:
            device_list = ", ".join(new_drives)
            if self.security.config.get("audit_logging", True):
                self.security.log_event("USB Device Detected", f"New devices: {device_list}")
            
            messagebox.showwarning("Unauthorized Device", 
                                 f"Unauthorized USB device detected: {device_list}\nPlease authenticate to allow access.")
            
            if not self.authenticate_user():
                self.disable_usb_ports()
                self.usb_enabled = False
                self.update_ui()
        except Exception as e:
            print(f"Error handling new device: {e}")
    
    def session_monitor(self):
        """Monitor session timeout"""
        while self.monitoring:
            try:
                time.sleep(60)  # Check every minute
                elapsed = (time.time() - self.last_activity) / 60
                timeout = self.security.config.get("session_timeout", 30)
                
                if elapsed > timeout:
                    self.root.after(0, self.session_timeout)
                    break
            except Exception as e:
                print(f"Error in session monitoring: {e}")
    
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
    
    try:
        root = tk.Tk()
        app = ImprovedUSBSecurityApp(root)
        
        def on_closing():
            app.monitoring = False
            root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
    except Exception as e:
        messagebox.showerror("Application Error", f"Failed to start application: {e}")

def is_admin():
    """Check if running with admin privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    main()
