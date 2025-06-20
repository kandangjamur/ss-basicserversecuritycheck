from datetime import datetime


class BaseChecker:
    def __init__(self, config):
        self.config = config

    def create_result(self, check_name, passed, message, severity="medium"):
        """Create a standardized result object"""
        return {
            "check_name": check_name,
            "passed": passed,
            "message": message,
            "severity": severity,
            "timestamp": datetime.now().isoformat(),
            "category": self.__class__.__name__.replace("Checker", "").replace("Security", "")
        }

    def run_command(self, command):
        """Execute shell command and return output"""
        import subprocess
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True)
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), 1
