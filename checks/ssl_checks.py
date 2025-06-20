import ssl
import socket
import subprocess
from datetime import datetime
from .base_checker import BaseChecker


class SSLChecker(BaseChecker):
    def __init__(self, config):
        super().__init__(config)
        self.domains = config.get('ssl', {}).get('domains', ['localhost'])

    def run_checks(self):
        """Run all SSL security checks"""
        results = []

        for domain in self.domains:
            results.append(self.check_ssl_grade(domain))
            results.append(self.check_ssl_certificate_expiry(domain))

        return results

    def check_ssl_grade(self, domain):
        """Check SSL certificate grade using SSL Labs API or testssl.sh"""
        try:
            # Using testssl.sh for local testing (if available)
            stdout, stderr, returncode = self.run_command(
                f"testssl.sh --grade-only {domain}")

            if returncode == 0 and 'A' in stdout:
                return self.create_result("SSL Certificate Grade", True, f"SSL grade appears to be A or better for {domain}")
            else:
                # Fallback to basic SSL connection test
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cipher = ssock.cipher()
                        if cipher and cipher[1] in ['TLSv1.2', 'TLSv1.3']:
                            return self.create_result("SSL Certificate Grade", True, f"Strong TLS version detected for {domain}")
                        else:
                            return self.create_result("SSL Certificate Grade", False, f"Weak TLS configuration for {domain}")
        except Exception as e:
            return self.create_result("SSL Certificate Grade", False, f"Error checking SSL grade for {domain}: {str(e)}")

    def check_ssl_certificate_expiry(self, domain):
        """Check SSL certificate expiration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days

                    if days_until_expiry > 30:
                        return self.create_result("SSL Certificate Expiry", True, f"Certificate valid for {days_until_expiry} days")
                    elif days_until_expiry > 0:
                        return self.create_result("SSL Certificate Expiry", False, f"Certificate expires in {days_until_expiry} days", "high")
                    else:
                        return self.create_result("SSL Certificate Expiry", False, "Certificate has expired", "critical")
        except Exception as e:
            return self.create_result("SSL Certificate Expiry", False, f"Error checking certificate expiry for {domain}: {str(e)}")
