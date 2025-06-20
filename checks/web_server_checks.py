import requests
import subprocess
from .base_checker import BaseChecker


class WebServerChecker(BaseChecker):
    def __init__(self, config):
        super().__init__(config)
        self.target_urls = config.get('web_server', {}).get(
            'target_urls', ['http://localhost'])

    def run_checks(self, target_host=None):
        """Run all web server security checks"""
        results = []

        if target_host:
            self.target_urls = [
                f"http://{target_host}", f"https://{target_host}"]

        for url in self.target_urls:
            results.append(self.check_server_version_hidden(url))
            results.append(self.check_platform_version_hidden(url))
            results.append(self.check_https_redirect(url))
            results.append(self.check_https_only(url))

        return results

    def check_server_version_hidden(self, url):
        """Check if server version is hidden"""
        try:
            response = requests.get(url, timeout=10)
            server_header = response.headers.get('Server', '')

            # Check if version info is exposed
            if any(word in server_header.lower() for word in ['apache/', 'nginx/', 'iis/']):
                return self.create_result("Web Server Version Hidden", False, f"Server version exposed: {server_header}")
            else:
                return self.create_result("Web Server Version Hidden", True, "Server version appears to be hidden")
        except Exception as e:
            return self.create_result("Web Server Version Hidden", False, f"Error checking server headers: {str(e)}")

    def check_platform_version_hidden(self, url):
        """Check if platform version is hidden"""
        try:
            response = requests.get(url, timeout=10)
            headers_to_check = ['X-Powered-By',
                                'X-AspNet-Version', 'X-AspNetMvc-Version']

            for header in headers_to_check:
                if header in response.headers:
                    return self.create_result("Platform Version Hidden", False, f"Platform version exposed in {header}: {response.headers[header]}")

            return self.create_result("Platform Version Hidden", True, "Platform version appears to be hidden")
        except Exception as e:
            return self.create_result("Platform Version Hidden", False, f"Error checking platform headers: {str(e)}")

    def check_https_redirect(self, url):
        """Check if HTTP redirects to HTTPS"""
        if not url.startswith('http://'):
            return self.create_result("HTTPS Redirect", True, "URL is already HTTPS")

        try:
            response = requests.get(url, allow_redirects=False, timeout=10)

            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    return self.create_result("HTTPS Redirect", True, "HTTP properly redirects to HTTPS")

            return self.create_result("HTTPS Redirect", False, "HTTP does not redirect to HTTPS")
        except Exception as e:
            return self.create_result("HTTPS Redirect", False, f"Error checking HTTPS redirect: {str(e)}")

    def check_https_only(self, url):
        """Check if application runs on HTTPS"""
        https_url = url.replace('http://', 'https://')

        try:
            response = requests.get(https_url, timeout=10, verify=False)
            if response.status_code == 200:
                return self.create_result("HTTPS Available", True, "Application accessible via HTTPS")
            else:
                return self.create_result("HTTPS Available", False, f"HTTPS not properly configured (status: {response.status_code})")
        except Exception as e:
            return self.create_result("HTTPS Available", False, f"HTTPS not accessible: {str(e)}")
