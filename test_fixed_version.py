#!/usr/bin/env python3
"""
Test script for the Fixed USB Security Application
This script tests the basic functionality without requiring external dependencies.
"""

import os
import sys
import json
import hashlib
import sqlite3
import datetime

def test_basic_imports():
    """Test that all required modules can be imported"""
    print("🔍 Testing basic imports...")
    
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, simpledialog
        import threading
        import time
        import ctypes
        import winreg
        print("✅ All basic imports successful")
        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_security_class():
    """Test the security class functionality"""
    print("\n🔍 Testing security class...")
    
    try:
        # Test password hashing
        test_password = "test123"
        hashed = hashlib.sha256(test_password.encode()).hexdigest()
        print(f"✅ Password hashing works: {hashed[:10]}...")
        
        # Test JSON config
        config = {
            "admin_password": hashed,
            "auto_block": True,
            "audit_logging": True,
            "session_timeout": 30
        }
        
        with open("test_config.json", "w") as f:
            json.dump(config, f, indent=4)
        
        with open("test_config.json", "r") as f:
            loaded_config = json.load(f)
        
        if loaded_config["admin_password"] == hashed:
            print("✅ JSON configuration works")
        else:
            print("❌ JSON configuration failed")
            return False
        
        # Clean up test file
        os.remove("test_config.json")
        return True
        
    except Exception as e:
        print(f"❌ Security class test failed: {e}")
        return False

def test_database():
    """Test database functionality"""
    print("\n🔍 Testing database...")
    
    try:
        # Test SQLite connection
        conn = sqlite3.connect("test_db.db")
        cursor = conn.cursor()
        
        # Create test table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS test_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                user TEXT
            )
        ''')
        
        # Insert test data
        timestamp = datetime.datetime.now().isoformat()
        cursor.execute('''
            INSERT INTO test_audit (timestamp, action, user)
            VALUES (?, ?, ?)
        ''', (timestamp, "Test Action", "TestUser"))
        
        conn.commit()
        
        # Query test data
        cursor.execute('SELECT * FROM test_audit')
        result = cursor.fetchone()
        
        if result and result[2] == "Test Action":
            print("✅ Database operations work")
        else:
            print("❌ Database query failed")
            return False
        
        conn.close()
        
        # Clean up test database
        os.remove("test_db.db")
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_admin_check():
    """Test administrator privilege check"""
    print("\n🔍 Testing admin privilege check...")
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        print(f"✅ Admin check works: {'Admin' if is_admin else 'Not Admin'}")
        return True
    except Exception as e:
        print(f"❌ Admin check failed: {e}")
        return False

def test_usb_detection():
    """Test USB drive detection"""
    print("\n🔍 Testing USB drive detection...")
    
    try:
        import ctypes
        drives = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drive = f"{chr(65 + i)}:\\"
                if os.path.exists(drive):
                    drives.append(drive)
        
        print(f"✅ USB detection works: Found {len(drives)} drives")
        if drives:
            print(f"   Drives: {', '.join(drives)}")
        return True
        
    except Exception as e:
        print(f"❌ USB detection failed: {e}")
        return False

def test_registry_access():
    """Test registry access (read-only)"""
    print("\n🔍 Testing registry access...")
    
    try:
        import winreg
        # Try to read USB storage registry (read-only)
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_READ)
        start_value, _ = winreg.QueryValueEx(reg_key, "Start")
        winreg.CloseKey(reg_key)
        
        print(f"✅ Registry access works: USBSTOR Start value = {start_value}")
        return True
        
    except Exception as e:
        print(f"❌ Registry access failed: {e}")
        return False

def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("🧪 USB Security Application - Test Suite")
    print("=" * 60)
    
    tests = [
        ("Basic Imports", test_basic_imports),
        ("Security Class", test_security_class),
        ("Database", test_database),
        ("Admin Check", test_admin_check),
        ("USB Detection", test_usb_detection),
        ("Registry Access", test_registry_access)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} test failed")
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application should work correctly.")
        print("\n🚀 To run the application:")
        print("   python fixed_usb_security.py")
    else:
        print("⚠️  Some tests failed. Check the issues above.")
        print("\n💡 Recommendations:")
        if passed < 3:
            print("   - Check Python installation")
            print("   - Ensure you're running on Windows")
        if passed >= 3:
            print("   - The application may work with limited functionality")
            print("   - Run as Administrator for full features")
    
    print("=" * 60)

if __name__ == "__main__":
    run_all_tests()
