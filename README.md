# Basic Server Security Checklist Tool

A comprehensive tool to verify basic security hardening configurations on servers.

## Features

- ✅ SSH security verification (password auth, root login, authorized keys)
- ✅ Web server security (version hiding, HTTPS configuration)
- ✅ SSL/TLS certificate health checks
- ✅ System security (fail2ban, ClamAV, open ports, file permissions)
- ✅ Database security checks
- ✅ Application security verification
- ✅ Multiple report formats (console, JSON, HTML)

## Installation

1. Clone or download this repository
2. Install Python dependencies:
   ```bash
   pip install requests
   ```
3. Make scripts executable:
   ```bash
   chmod +x scripts/quick_check.sh
   chmod +x security_checker.py
   ```

## Usage

### Quick Check (Bash)
```bash
./scripts/quick_check.sh
```

### Full Security Check (Python)
```bash
# Basic usage
python3 security_checker.py

# Check specific host
python3 security_checker.py --host example.com

# Generate JSON report
python3 security_checker.py --format json --output report.json

# Generate HTML report
python3 security_checker.py --format html --output report.html

# Use custom config
python3 security_checker.py --config custom_config.json
```

## Configuration

Edit `config/security_config.json` to customize:
- SSH authorized public keys
- Target URLs and domains
- Database connection details
- Web application paths
- Cloudflare settings

## Security Checks Covered

### Mandatory Checks
- [x] Disable password authentication for SSH access
- [x] Ensure only authorized SSH access
- [x] Hide web server version
- [x] Hide platform version  
- [x] All web application must run on HTTPS
- [x] Check SSL certificate health (A grade)
- [x] Redirect all HTTP access to HTTPS
- [x] Setup fail2ban protection
- [x] Check file permissions and ownership
- [x] Restrict public access to GIT directory
- [x] Install ClamAV
- [x] Ensure only necessary ports are exposed
- [x] Disable root login via SSH
- [x] Check robots.txt configuration
- [x] Verify production environment configuration
- [x] Check Cloudflare proxy status

## Requirements

- Python 3.6+
- Linux/Unix system
- Root or sudo access for system checks
- Network access for SSL/web checks

## Output Examples

The tool provides detailed reports showing:
- Overall security score
- Individual check results
- Recommendations for failed checks
- Severity levels for issues

## Contributing

Feel free to contribute additional security checks or improvements!
