import json
from datetime import datetime


class ReportGenerator:
    def __init__(self, results):
        self.results = results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_console_report(self):
        """Generate a console-friendly report"""
        report = f"\n🔒 Security Checklist Report - {self.timestamp}\n"
        report += "=" * 60 + "\n"

        passed = sum(1 for r in self.results if r['passed'])
        total = len(self.results)

        report += f"Overall Score: {passed}/{total} ({(passed/total*100):.1f}%)\n\n"

        # Group by category
        categories = {}
        for result in self.results:
            category = result.get('category', 'Other')
            if category not in categories:
                categories[category] = []
            categories[category].append(result)

        for category, checks in categories.items():
            report += f"📋 {category} Checks\n"
            report += "-" * 30 + "\n"

            for check in checks:
                status = "✅ PASS" if check['passed'] else "❌ FAIL"
                report += f"{status} {check['check_name']}\n"
                report += f"     {check['message']}\n\n"

        return report

    def generate_json_report(self):
        """Generate a JSON report"""
        report_data = {
            "timestamp": self.timestamp,
            "summary": {
                "total_checks": len(self.results),
                "passed": sum(1 for r in self.results if r['passed']),
                "failed": sum(1 for r in self.results if not r['passed'])
            },
            "results": self.results
        }
        return json.dumps(report_data, indent=2)

    def generate_html_report(self):
        """Generate an HTML report"""
        passed = sum(1 for r in self.results if r['passed'])
        total = len(self.results)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Checklist Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
        .pass {{ color: green; }}
        .fail {{ color: red; }}
        .check {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
        .check.pass {{ border-left-color: green; }}
        .check.fail {{ border-left-color: red; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Checklist Report</h1>
        <p>Generated: {self.timestamp}</p>
        <p>Score: {passed}/{total} ({(passed/total*100):.1f}%)</p>
    </div>
    
    <div class="results">
"""

        for result in self.results:
            status_class = "pass" if result['passed'] else "fail"
            status_text = "PASS" if result['passed'] else "FAIL"

            html += f"""
        <div class="check {status_class}">
            <h3>{result['check_name']} - <span class="{status_class}">{status_text}</span></h3>
            <p>{result['message']}</p>
        </div>
"""

        html += """
    </div>
</body>
</html>
"""
        return html
