import json
import os


class ConfigLoader:
    @staticmethod
    def load_config(config_file):
        """Load configuration from JSON file with fallback defaults"""
        default_config = {
            "ssh": {
                "authorized_public_keys": []
            },
            "web_server": {
                "target_urls": ["http://localhost"]
            },
            "ssl": {
                "domains": ["localhost"]
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
                "web_roots": ["/var/www/html", "/usr/share/nginx/html"],
                "config_files": [".env", "config.php", "settings.py"]
            },
            "cloudflare": {
                "check_proxy": True,
                "expected_headers": ["cf-ray", "cf-cache-status"]
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                
                # Merge user config with defaults
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
                        
                return default_config
            except Exception as e:
                print(f"Warning: Could not load config file {config_file}: {e}")
                print("Using default configuration...")
                return default_config
        else:
            print(f"Config file {config_file} not found. Using default configuration...")
            return default_config
