#!/usr/bin/env python3
"""
USB Physical Security - Upgrade Installation Script
This script helps install and configure the upgraded USB security application.
"""

import os
import sys
import subprocess
import json
import hashlib
from pathlib import Path

def print_banner():
    """Print installation banner"""
    print("=" * 60)
    print("🔒 USB Physical Security - Upgrade Installation")
    print("=" * 60)
    print("This script will install the upgraded version of the USB security tool.")
    print("The upgrade includes enhanced security features and modern UI.")
    print("=" * 60)

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Error: Python 3.7 or higher is required.")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_admin_rights():
    """Check if running with admin privileges"""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✅ Running with administrator privileges")
        else:
            print("⚠️  Warning: Not running as administrator")
            print("   The application requires admin rights to control USB ports")
        return is_admin
    except:
        print("⚠️  Warning: Could not verify administrator privileges")
        return False

def install_dependencies():
    """Install required dependencies"""
    print("\n📦 Installing dependencies...")
    
    requirements = [
        "cryptography>=3.4.8",
        "psutil>=5.8.0"
    ]
    
    for package in requirements:
        try:
            print(f"Installing {package}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {package}")
            return False
    
    return True

def create_config():
    """Create initial configuration"""
    print("\n⚙️  Creating configuration...")
    
    config = {
        "admin_password": hashlib.sha256("admin123".encode()).hexdigest(),
        "auto_block": True,
        "audit_logging": True,
        "session_timeout": 30,
        "theme": "dark"
    }
    
    try:
        with open("upgraded_config.json", "w") as f:
            json.dump(config, f, indent=4)
        print("✅ Configuration file created")
        return True
    except Exception as e:
        print(f"❌ Failed to create configuration: {e}")
        return False

def setup_database():
    """Setup SQLite database"""
    print("\n🗄️  Setting up database...")
    
    try:
        import sqlite3
        conn = sqlite3.connect("security_audit.db")
        cursor = conn.cursor()
        
        # Create audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                user TEXT,
                details TEXT
            )
        ''')
        
        # Create whitelist table
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
        print("✅ Database setup completed")
        return True
    except Exception as e:
        print(f"❌ Failed to setup database: {e}")
        return False

def create_shortcut():
    """Create desktop shortcut"""
    print("\n🔗 Creating desktop shortcut...")
    
    try:
        desktop = Path.home() / "Desktop"
        shortcut_path = desktop / "USB Security Upgraded.lnk"
        
        # Create a simple batch file as alternative
        batch_content = f'''@echo off
cd /d "{os.getcwd()}"
python upgraded_usb_security.py
pause
'''
        
        batch_path = desktop / "USB Security Upgraded.bat"
        with open(batch_path, "w") as f:
            f.write(batch_content)
        
        print("✅ Desktop shortcut created")
        return True
    except Exception as e:
        print(f"⚠️  Could not create shortcut: {e}")
        return False

def verify_installation():
    """Verify installation"""
    print("\n🔍 Verifying installation...")
    
    required_files = [
        "upgraded_usb_security.py",
        "security_core.py",
        "requirements.txt",
        "UPGRADE_README.md"
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing files: {', '.join(missing_files)}")
        return False
    
    print("✅ All required files found")
    return True

def show_usage_instructions():
    """Show usage instructions"""
    print("\n" + "=" * 60)
    print("🎉 Installation Complete!")
    print("=" * 60)
    print("\n📋 Usage Instructions:")
    print("1. Run the application as Administrator:")
    print("   python upgraded_usb_security.py")
    print("\n2. Default password: admin123")
    print("3. Change the password in Settings tab")
    print("4. Configure security settings as needed")
    print("\n📁 Files created:")
    print("- upgraded_config.json (configuration)")
    print("- security_audit.db (audit logs)")
    print("- USB Security Upgraded.bat (desktop shortcut)")
    print("\n📖 For detailed information, see UPGRADE_README.md")
    print("=" * 60)

def main():
    """Main installation function"""
    print_banner()
    
    # Check prerequisites
    if not check_python_version():
        input("Press Enter to exit...")
        return
    
    check_admin_rights()
    
    # Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        input("Press Enter to exit...")
        return
    
    # Create configuration
    if not create_config():
        print("❌ Failed to create configuration")
        input("Press Enter to exit...")
        return
    
    # Setup database
    if not setup_database():
        print("❌ Failed to setup database")
        input("Press Enter to exit...")
        return
    
    # Create shortcut
    create_shortcut()
    
    # Verify installation
    if not verify_installation():
        print("❌ Installation verification failed")
        input("Press Enter to exit...")
        return
    
    # Show instructions
    show_usage_instructions()
    
    # Ask if user wants to run the application
    response = input("\n🚀 Would you like to run the application now? (y/n): ")
    if response.lower() in ['y', 'yes']:
        try:
            print("Starting USB Security application...")
            subprocess.run([sys.executable, "upgraded_usb_security.py"])
        except Exception as e:
            print(f"❌ Failed to start application: {e}")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
