import subprocess
import pymysql
import psycopg2
from .base_checker import BaseChecker


class DatabaseChecker(BaseChecker):
    def __init__(self, config):
        super().__init__(config)
        self.mysql_config = config.get('database', {}).get('mysql', {})
        self.postgresql_config = config.get('database', {}).get('postgresql', {})

    def run_checks(self):
        """Run all database security checks"""
        results = []
        
        results.append(self.check_mysql_root_access())
        results.append(self.check_postgresql_superuser_access())
        results.append(self.check_database_passwords())
        
        return results

    def check_mysql_root_access(self):
        """Check if application uses root MySQL access"""
        try:
            # Check if MySQL is running
            stdout, stderr, returncode = self.run_command("systemctl is-active mysql || systemctl is-active mariadb")
            
            if returncode != 0:
                return self.create_result("MySQL Root Access", True, "MySQL/MariaDB is not running")
            
            # Check for root user in application configs
            web_roots = ['/var/www', '/var/www/html', '/usr/share/nginx/html']
            root_usage_found = []
            
            for root in web_roots:
                stdout, stderr, returncode = self.run_command(f"find {root} -type f -name '*.php' -o -name '*.py' -o -name '*.js' -o -name '.env' 2>/dev/null | xargs grep -l 'root.*password' 2>/dev/null")
                if stdout.strip():
                    root_usage_found.extend(stdout.strip().split('\n'))
            
            if root_usage_found:
                return self.create_result("MySQL Root Access", False, f"Potential root database usage found in: {', '.join(root_usage_found[:3])}")
            else:
                return self.create_result("MySQL Root Access", True, "No obvious root database usage found in application files")
                
        except Exception as e:
            return self.create_result("MySQL Root Access", False, f"Error checking MySQL root access: {str(e)}")

    def check_postgresql_superuser_access(self):
        """Check if application uses PostgreSQL superuser access"""
        try:
            # Check if PostgreSQL is running
            stdout, stderr, returncode = self.run_command("systemctl is-active postgresql")
            
            if returncode != 0:
                return self.create_result("PostgreSQL Superuser Access", True, "PostgreSQL is not running")
            
            # Check for postgres/superuser usage in configs
            web_roots = ['/var/www', '/var/www/html', '/usr/share/nginx/html']
            superuser_usage_found = []
            
            for root in web_roots:
                stdout, stderr, returncode = self.run_command(f"find {root} -type f -name '*.py' -o -name '*.js' -o -name '.env' 2>/dev/null | xargs grep -l 'postgres.*password\\|superuser' 2>/dev/null")
                if stdout.strip():
                    superuser_usage_found.extend(stdout.strip().split('\n'))
            
            if superuser_usage_found:
                return self.create_result("PostgreSQL Superuser Access", False, f"Potential superuser database usage found")
            else:
                return self.create_result("PostgreSQL Superuser Access", True, "No obvious superuser database usage found")
                
        except Exception as e:
            return self.create_result("PostgreSQL Superuser Access", False, f"Error checking PostgreSQL superuser access: {str(e)}")

    def check_database_passwords(self):
        """Check for strong database passwords in configuration"""
        try:
            weak_patterns = ['password', '123456', 'admin', 'root', 'test', '']
            config_files = ['.env', 'config.php', 'settings.py', 'database.yml']
            weak_passwords_found = []
            
            for config_file in config_files:
                stdout, stderr, returncode = self.run_command(f"find /var/www /usr/share/nginx/html -name '{config_file}' 2>/dev/null")
                if stdout.strip():
                    for file_path in stdout.strip().split('\n'):
                        for pattern in weak_patterns:
                            stdout2, stderr2, returncode2 = self.run_command(f"grep -i 'password.*{pattern}' {file_path} 2>/dev/null")
                            if stdout2.strip():
                                weak_passwords_found.append(file_path)
                                break
            
            if weak_passwords_found:
                return self.create_result("Database Password Strength", False, f"Weak database passwords found in: {', '.join(weak_passwords_found)}")
            else:
                return self.create_result("Database Password Strength", True, "No obvious weak database passwords found")
                
        except Exception as e:
            return self.create_result("Database Password Strength", False, f"Error checking database passwords: {str(e)}")
