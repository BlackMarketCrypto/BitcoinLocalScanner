#!/usr/bin/env python3
"""
Bitcoin Local Scanner v1.0 Compilation Script
Compiles bitcoin_local_scanner.py into a standalone executable
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_pyinstaller():
    """Check if PyInstaller is installed"""
    try:
        import PyInstaller
        print("✓ PyInstaller is installed")
        return True
    except ImportError:
        print("✗ PyInstaller not found. Installing...")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
            print("✓ PyInstaller installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("✗ Failed to install PyInstaller")
            return False

def compile_to_exe():
    """Compile bitcoin_local_scanner.py to executable"""
    script_name = "bitcoin_local_scanner.py"
    exe_name = "BitcoinLocalScanner"
    
    if not os.path.exists(script_name):
        print(f"✗ {script_name} not found in current directory")
        return False
    
    print(f"\n🔨 Compiling {script_name} to {exe_name}.exe...")
    
    # PyInstaller command with necessary options
    cmd = [
        "pyinstaller",
        "--onefile",                    # Create single executable
        "--console",                    # Console application
        "--name", exe_name,             # Output name
        "--distpath", "BitcoinLocalScanner_Distribution",  # Distribution folder
        "--workpath", "build_temp",     # Temporary build folder
        "--specpath", "build_temp",     # Spec file location
        "--clean",                      # Clean cache
        "--noconfirm",                  # Overwrite without confirmation
        
        # Hidden imports for dependencies
        "--hidden-import", "mnemonic",
        "--hidden-import", "bip32",
        "--hidden-import", "colorama",
        "--hidden-import", "sqlite3",
        "--hidden-import", "hashlib",
        "--hidden-import", "struct",
        "--hidden-import", "threading",
        "--hidden-import", "concurrent.futures",
        "--hidden-import", "configparser",
        "--hidden-import", "glob",
        "--hidden-import", "shutil",
        "--hidden-import", "time",
        "--hidden-import", "os",
        "--hidden-import", "sys",
        
        # Cryptographic libraries
        "--hidden-import", "Crypto",
        "--hidden-import", "Crypto.Hash",
        "--hidden-import", "Crypto.Hash.RIPEMD160",
        "--hidden-import", "Crypto.Hash.SHA256",
        "--hidden-import", "ecdsa",
        "--hidden-import", "base58",
        "--hidden-import", "bech32",
        
        script_name
    ]
    
    try:
        # Run PyInstaller
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print("✓ Compilation successful!")
        
        # Clean up build artifacts
        if os.path.exists("build_temp"):
            shutil.rmtree("build_temp")
            print("✓ Cleaned up build artifacts")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Compilation failed: {e}")
        if e.stdout:
            print(f"STDOUT: {e.stdout}")
        if e.stderr:
            print(f"STDERR: {e.stderr}")
        return False

def copy_config_files():
    """Copy configuration files to distribution folder"""
    dist_folder = "BitcoinLocalScanner_Distribution"
    
    if not os.path.exists(dist_folder):
        print(f"✗ Distribution folder {dist_folder} not found")
        return False
    
    files_to_copy = [
        "config.txt"
    ]
    
    print(f"\n📁 Copying configuration files to {dist_folder}...")
    
    for file in files_to_copy:
        if os.path.exists(file):
            shutil.copy2(file, dist_folder)
            print(f"✓ Copied {file}")
        else:
            print(f"⚠ {file} not found, skipping")
    
    return True

def main():
    """Main compilation function"""
    print("="*60)
    print("Bitcoin Local Scanner v1.0 - Compilation Script")
    print("="*60)
    
    # Check PyInstaller
    if not check_pyinstaller():
        return False
    
    # Compile to executable
    if not compile_to_exe():
        return False
    
    # Copy configuration files
    if not copy_config_files():
        return False
    
    print("\n" + "="*60)
    print("🎉 COMPILATION COMPLETE!")
    print("="*60)
    print(f"📦 Executable created: BitcoinLocalScanner_Distribution/BitcoinLocalScanner.exe")
    print(f"📄 Configuration file: BitcoinLocalScanner_Distribution/config.txt")
    print("\n💡 Next steps:")
    print("   1. Edit config.txt to set your Bitcoin blockchain path")
    print("   2. Run BitcoinLocalScanner.exe to start scanning")
    print("   3. Check bitcoin_wallets_with_balance.txt for results")
    print("="*60)
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)