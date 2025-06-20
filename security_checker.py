#!/usr/bin/env python3
"""
Basic Server Security Checklist Tool
Verifies essential security hardening configurations
"""

import json
import sys
import argparse
from datetime import datetime
from checks.ssh_checks import SSHSecurityChecker
from checks.web_server_checks import WebServerChecker
from checks.ssl_checks import SSLChecker
from checks.system_checks import SystemSecurityChecker
from checks.database_checks import DatabaseChecker
from checks.application_checks import ApplicationChecker
from utils.report_generator import ReportGenerator
from utils.config_loader import ConfigLoader


class SecurityChecklist:
    def __init__(self, config_file="config/security_config.json"):
        self.config = ConfigLoader.load_config(config_file)
        self.results = []

    def run_all_checks(self, target_host=None):
        """Run all security checks"""
        print("🔍 Starting Basic Security Checklist...")

        # SSH Security Checks
        ssh_checker = SSHSecurityChecker(self.config)
        self.results.extend(ssh_checker.run_checks(target_host))

        # Web Server Checks
        web_checker = WebServerChecker(self.config)
        self.results.extend(web_checker.run_checks(target_host))

        # SSL/TLS Checks
        ssl_checker = SSLChecker(self.config)
        self.results.extend(ssl_checker.run_checks())

        # System Security Checks
        system_checker = SystemSecurityChecker(self.config)
        self.results.extend(system_checker.run_checks())

        # Database Security Checks
        db_checker = DatabaseChecker(self.config)
        self.results.extend(db_checker.run_checks())

        # Application Checks
        app_checker = ApplicationChecker(self.config)
        self.results.extend(app_checker.run_checks())

        return self.results

    def generate_report(self, format_type="console"):
        """Generate security report"""
        generator = ReportGenerator(self.results)
        if format_type == "json":
            return generator.generate_json_report()
        elif format_type == "html":
            return generator.generate_html_report()
        else:
            return generator.generate_console_report()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Basic Server Security Checklist Tool")
    parser.add_argument(
        "--host", help="Target host to check (default: localhost)")
    parser.add_argument("--config", help="Config file path",
                        default="config/security_config.json")
    parser.add_argument(
        "--format", choices=["console", "json", "html"], default="console", help="Report format")
    parser.add_argument("--output", help="Output file for report")

    args = parser.parse_args()

    checker = SecurityChecklist(args.config)
    results = checker.run_all_checks(args.host)

    report = checker.generate_report(args.format)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)
