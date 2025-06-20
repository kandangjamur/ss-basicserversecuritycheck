#!/usr/bin/env python3

import os
import sys

def install_dependencies():
    """Install core dependencies"""
    try:
        import requests
        print("✅ requests is already installed")
    except ImportError:
        print("📦 Installing requests...")
        os.system(f"{sys.executable} -m pip install requests")
    
    # Check optional dependencies
    try:
        import pymysql
        print("✅ pymysql is available (optional)")
    except ImportError:
        print("⚠️  pymysql not installed (optional - for database connection testing)")
    
    try:
        import psycopg2
        print("✅ psycopg2 is available (optional)")
    except ImportError:
        print("⚠️  psycopg2 not installed (optional - for PostgreSQL connection testing)")

def create_directories():
    """Create necessary directories"""
    dirs = ['config', 'reports', 'logs']
    for dir_name in dirs:
        os.makedirs(dir_name, exist_ok=True)
        print(f"📁 Created/verified directory: {dir_name}")

def create_default_config():
    """Create default configuration if it doesn't exist"""
    config_path = "config/security_config.json"
    if not os.path.exists(config_path):
        default_config = """{
  "ssh": {
    "authorized_public_keys": [
      "# Add your authorized SSH public keys here",
      "# Example: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... user@domain.com"
    ]
  },
  "web_server": {
    "target_urls": [
      "http://localhost",
      "https://localhost"
    ]
  },
  "ssl": {
    "domains": [
      "localhost"
    ]
  },
  "database": {
    "mysql": {
      "host": "localhost",
      "port": 3306
    },
    "postgresql": {
      "host": "localhost", 
      "port": 5432
    }
  },
  "application": {
    "web_roots": [
      "/var/www/html",
      "/usr/share/nginx/html"
    ],
    "config_files": [
      ".env",
      "config.php",
      "settings.py"
    ]
  },
  "cloudflare": {
    "check_proxy": true,
    "expected_headers": ["cf-ray", "cf-cache-status"]
  }
}"""
        with open(config_path, 'w') as f:
            f.write(default_config)
        print(f"📝 Created default config: {config_path}")

if __name__ == "__main__":
    print("🔧 Setting up Basic Server Security Checklist Tool...")
    
    install_dependencies()
    create_directories()
    create_default_config()
    
    print("\n✅ Setup completed!")
    print("\n📖 Usage:")
    print("  python3 security_checker.py")
    print("  python3 security_checker.py --host example.com")
    print("  python3 security_checker.py --format json --output report.json")
    print("\n📝 Edit config/security_config.json to customize your settings")
