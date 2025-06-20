import os
import requests
from .base_checker import BaseChecker


class ApplicationChecker(BaseChecker):
    def __init__(self, config):
        super().__init__(config)
        self.web_roots = config.get('application', {}).get('web_roots', ['/var/www/html'])
        self.target_urls = config.get('web_server', {}).get('target_urls', ['http://localhost'])

    def run_checks(self):
        """Run all application security checks"""
        results = []
        
        results.append(self.check_robots_txt())
        results.append(self.check_production_config())
        results.append(self.check_cloudflare_proxy())
        results.append(self.check_test_data_cleanup())
        
        return results

    def check_robots_txt(self):
        """Check if robots.txt is properly configured"""
        try:
            for url in self.target_urls:
                if url.startswith('http://'):
                    robots_url = f"{url}/robots.txt"
                else:
                    robots_url = f"{url}/robots.txt"
                
                try:
                    response = requests.get(robots_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text.lower()
                        if 'disallow:' in content and 'user-agent:' in content:
                            return self.create_result("Robots.txt Configuration", True, "robots.txt is properly configured")
                        else:
                            return self.create_result("Robots.txt Configuration", False, "robots.txt exists but may not be properly configured")
                    else:
                        return self.create_result("Robots.txt Configuration", False, "robots.txt is not accessible")
                except:
                    continue
            
            return self.create_result("Robots.txt Configuration", False, "robots.txt could not be checked")
                
        except Exception as e:
            return self.create_result("Robots.txt Configuration", False, f"Error checking robots.txt: {str(e)}")

    def check_production_config(self):
        """Check if application is configured for production environment"""
        try:
            debug_indicators = []
            
            # Check for debug settings in common config files
            config_patterns = [
                ('*.env', 'APP_DEBUG=true'),
                ('*.py', 'DEBUG = True'),
                ('*.php', 'error_reporting.*E_ALL'),
                ('*.js', 'console.log'),
                ('*.php', 'display_errors.*On')
            ]
            
            for web_root in self.web_roots:
                if os.path.exists(web_root):
                    for pattern, debug_string in config_patterns:
                        stdout, stderr, returncode = self.run_command(f"find {web_root} -name '{pattern}' -exec grep -l '{debug_string}' {{}} \\; 2>/dev/null")
                        if stdout.strip():
                            debug_indicators.extend(stdout.strip().split('\n'))
            
            if debug_indicators:
                return self.create_result("Production Configuration", False, f"Debug settings found in: {', '.join(debug_indicators[:3])}")
            else:
                return self.create_result("Production Configuration", True, "No obvious debug settings found")
                
        except Exception as e:
            return self.create_result("Production Configuration", False, f"Error checking production config: {str(e)}")

    def check_cloudflare_proxy(self):
        """Check if site is proxied through Cloudflare"""
        try:
            cloudflare_headers = ['cf-ray', 'cf-cache-status', 'server: cloudflare']
            
            for url in self.target_urls:
                try:
                    response = requests.get(url, timeout=10)
                    headers = {k.lower(): v.lower() for k, v in response.headers.items()}
                    
                    cloudflare_detected = any(
                        header in headers or 
                        any(cf_header in headers for cf_header in cloudflare_headers)
                        for header in cloudflare_headers
                    )
                    
                    if cloudflare_detected or 'cloudflare' in headers.get('server', ''):
                        return self.create_result("Cloudflare Proxy", True, "Cloudflare proxy detected")
                    
                except:
                    continue
            
            return self.create_result("Cloudflare Proxy", False, "Cloudflare proxy not detected")
                
        except Exception as e:
            return self.create_result("Cloudflare Proxy", False, f"Error checking Cloudflare proxy: {str(e)}")

    def check_test_data_cleanup(self):
        """Check for test data and development artifacts"""
        try:
            test_artifacts = []
            test_patterns = [
                'test.php',
                'phpinfo.php',
                'info.php',
                'test.html',
                'development.log',
                'debug.log',
                'test_*',
                'demo_*'
            ]
            
            for web_root in self.web_roots:
                if os.path.exists(web_root):
                    for pattern in test_patterns:
                        stdout, stderr, returncode = self.run_command(f"find {web_root} -name '{pattern}' 2>/dev/null")
                        if stdout.strip():
                            test_artifacts.extend(stdout.strip().split('\n'))
            
            if test_artifacts:
                return self.create_result("Test Data Cleanup", False, f"Test artifacts found: {', '.join(test_artifacts[:5])}")
            else:
                return self.create_result("Test Data Cleanup", True, "No obvious test artifacts found")
                
        except Exception as e:
            return self.create_result("Test Data Cleanup", False, f"Error checking test data: {str(e)}")
