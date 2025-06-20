import os
import subprocess
from .base_checker import BaseChecker


class SystemSecurityChecker(BaseChecker):
    def __init__(self, config):
        super().__init__(config)

    def run_checks(self):
        """Run all system security checks"""
        results = []

        results.append(self.check_fail2ban_installed())
        results.append(self.check_clamav_installed())
        results.append(self.check_open_ports())
        results.append(self.check_file_permissions())
        results.append(self.check_git_directory_access())

        return results

    def check_fail2ban_installed(self):
        """Check if fail2ban is installed and running"""
        try:
            stdout, stderr, returncode = self.run_command(
                "systemctl is-active fail2ban")

            if returncode == 0 and 'active' in stdout:
                return self.create_result("Fail2ban Protection", True, "Fail2ban is installed and active")
            else:
                return self.create_result("Fail2ban Protection", False, "Fail2ban is not active or not installed")
        except Exception as e:
            return self.create_result("Fail2ban Protection", False, f"Error checking fail2ban: {str(e)}")

    def check_clamav_installed(self):
        """Check if ClamAV is installed"""
        try:
            stdout, stderr, returncode = self.run_command("which clamscan")

            if returncode == 0:
                return self.create_result("ClamAV Antivirus", True, "ClamAV is installed")
            else:
                return self.create_result("ClamAV Antivirus", False, "ClamAV is not installed")
        except Exception as e:
            return self.create_result("ClamAV Antivirus", False, f"Error checking ClamAV: {str(e)}")

    def check_open_ports(self):
        """Check for unnecessary open ports"""
        try:
            stdout, stderr, returncode = self.run_command(
                "netstat -tuln | grep LISTEN")

            if returncode == 0:
                lines = stdout.strip().split('\n')
                public_ports = []

                for line in lines:
                    if '0.0.0.0:' in line:
                        port = line.split('0.0.0.0:')[1].split()[0]
                        public_ports.append(port)

                # Common necessary ports
                necessary_ports = ['22', '80', '443']
                unnecessary_ports = [
                    port for port in public_ports if port not in necessary_ports]

                if unnecessary_ports:
                    return self.create_result("Open Ports Check", False, f"Unnecessary public ports detected: {', '.join(unnecessary_ports)}")
                else:
                    return self.create_result("Open Ports Check", True, "Only necessary ports are publicly exposed")
            else:
                return self.create_result("Open Ports Check", False, "Could not check open ports")
        except Exception as e:
            return self.create_result("Open Ports Check", False, f"Error checking open ports: {str(e)}")

    def check_file_permissions(self):
        """Check critical file permissions"""
        try:
            critical_files = [
                ('/etc/passwd', '644'),
                ('/etc/shadow', '640'),
                ('/etc/ssh/sshd_config', '600')
            ]

            issues = []
            for file_path, expected_perm in critical_files:
                if os.path.exists(file_path):
                    actual_perm = oct(os.stat(file_path).st_mode)[-3:]
                    if actual_perm != expected_perm:
                        issues.append(
                            f"{file_path}: {actual_perm} (expected {expected_perm})")

            if issues:
                return self.create_result("File Permissions", False, f"Permission issues: {'; '.join(issues)}")
            else:
                return self.create_result("File Permissions", True, "Critical file permissions are correct")
        except Exception as e:
            return self.create_result("File Permissions", False, f"Error checking file permissions: {str(e)}")

    def check_git_directory_access(self):
        """Check if .git directories are publicly accessible"""
        try:
            # This would need to be enhanced to check web-accessible directories
            web_roots = ['/var/www', '/var/www/html', '/usr/share/nginx/html']
            git_dirs_found = []

            for root in web_roots:
                if os.path.exists(root):
                    stdout, stderr, returncode = self.run_command(
                        f"find {root} -type d -name '.git' 2>/dev/null")
                    if stdout.strip():
                        git_dirs_found.extend(stdout.strip().split('\n'))

            if git_dirs_found:
                return self.create_result("Git Directory Protection", False, f"Git directories found in web roots: {', '.join(git_dirs_found)}")
            else:
                return self.create_result("Git Directory Protection", True, "No git directories found in web-accessible locations")
        except Exception as e:
            return self.create_result("Git Directory Protection", False, f"Error checking git directories: {str(e)}")
