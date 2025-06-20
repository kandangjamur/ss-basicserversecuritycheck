import subprocess
import re
import os
from .base_checker import BaseChecker


class SSHSecurityChecker(BaseChecker):
    def __init__(self, config):
        super().__init__(config)
        self.ssh_config_path = "/etc/ssh/sshd_config"

    def run_checks(self, target_host=None):
        """Run all SSH security checks"""
        results = []

        results.append(self.check_password_auth_disabled())
        results.append(self.check_root_login_disabled())
        results.append(self.check_authorized_keys())

        return results

    def check_password_auth_disabled(self):
        """Check if password authentication is disabled"""
        try:
            if os.path.exists(self.ssh_config_path):
                with open(self.ssh_config_path, 'r') as f:
                    content = f.read()

                # Check for PasswordAuthentication no
                if re.search(r'^\s*PasswordAuthentication\s+no', content, re.MULTILINE):
                    return self.create_result("SSH Password Authentication", True, "Password authentication is disabled")
                else:
                    return self.create_result("SSH Password Authentication", False, "Password authentication is not explicitly disabled")
            else:
                return self.create_result("SSH Password Authentication", False, "SSH config file not found")
        except Exception as e:
            return self.create_result("SSH Password Authentication", False, f"Error checking SSH config: {str(e)}")

    def check_root_login_disabled(self):
        """Check if root login is disabled"""
        try:
            if os.path.exists(self.ssh_config_path):
                with open(self.ssh_config_path, 'r') as f:
                    content = f.read()

                if re.search(r'^\s*PermitRootLogin\s+no', content, re.MULTILINE):
                    return self.create_result("SSH Root Login", True, "Root login is disabled")
                else:
                    return self.create_result("SSH Root Login", False, "Root login is not disabled")
            else:
                return self.create_result("SSH Root Login", False, "SSH config file not found")
        except Exception as e:
            return self.create_result("SSH Root Login", False, f"Error checking SSH config: {str(e)}")

    def check_authorized_keys(self):
        """Check if only authorized keys are present"""
        try:
            authorized_keys = self.config.get(
                'ssh', {}).get('authorized_public_keys', [])

            # Check root authorized keys
            root_keys_path = "/root/.ssh/authorized_keys"
            if os.path.exists(root_keys_path):
                with open(root_keys_path, 'r') as f:
                    keys_content = f.read()

                # Basic check - this would need to be enhanced for production
                if any(key in keys_content for key in authorized_keys):
                    return self.create_result("Authorized SSH Keys", True, "Authorized keys found")
                else:
                    return self.create_result("Authorized SSH Keys", False, "No recognized authorized keys found")
            else:
                return self.create_result("Authorized SSH Keys", False, "No authorized_keys file found")
        except Exception as e:
            return self.create_result("Authorized SSH Keys", False, f"Error checking authorized keys: {str(e)}")
