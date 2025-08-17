import os
import json
import hashlib
import base64
import datetime
import sqlite3
from cryptography.fernet import Fernet
import socket

class EnhancedUSBSecurity:
    def __init__(self):
        self.config_file = "usb_security_config.json"
        self.db_file = "usb_security.db"
        self.encryption_key = self.get_or_create_key()
        self.cipher = Fernet(self.encryption_key)
        self.setup_database()
        self.load_config()
        
    def get_or_create_key(self):
        """Get existing encryption key or create new one"""
        key_file = "encryption.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key
    
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
                details TEXT,
                ip_address TEXT
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
    
    def log_audit_event(self, action, details=""):
        """Log security events to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now().isoformat()
        user = os.getenv('USERNAME', 'Unknown')
        ip_address = self.get_local_ip()
        
        cursor.execute('''
            INSERT INTO audit_log (timestamp, action, user, details, ip_address)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, action, user, details, ip_address))
        conn.commit()
        conn.close()
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def encrypt_password(self, password):
        """Encrypt password using Fernet"""
        return self.cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt password using Fernet"""
        return self.cipher.decrypt(encrypted_password.encode()).decode()
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                "admin_password": self.encrypt_password("admin123"),
                "auto_block": True,
                "whitelist_enabled": False,
                "audit_logging": True,
                "session_timeout": 30,
                "theme": "dark"
            }
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def verify_password(self, password):
        """Verify password against stored encrypted password"""
        try:
            stored_password = self.decrypt_password(self.config["admin_password"])
            return password == stored_password
        except:
            return False
