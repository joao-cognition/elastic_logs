#!/usr/bin/env python3
"""
Security Report Generator for Elastic Logs.

Analyzes log files for:
- status_code=401/403 entries
- Unique IPs with >10 failed requests
- SQL/XSS patterns in request_path
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def load_logs(log_paths: list[Path]) -> list[dict[str, Any]]:
    """Load and combine logs from multiple JSON files."""
    all_logs = []
    for path in log_paths:
        if path.exists():
            with open(path, "r") as f:
                logs = json.load(f)
                all_logs.extend(logs)
    return all_logs


def find_auth_failures(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find all entries with status_code 401 or 403."""
    auth_failures = []
    for log in logs:
        http = log.get("http", {})
        status_code = http.get("status_code")
        if status_code in (401, 403):
            auth_failures.append({
                "timestamp": log.get("@timestamp"),
                "log_id": log.get("log_id"),
                "service": log.get("service"),
                "host": log.get("host"),
                "method": http.get("method"),
                "endpoint": http.get("endpoint"),
                "status_code": status_code,
                "client_ip": log.get("client", {}).get("ip"),
                "user_agent": log.get("client", {}).get("user_agent"),
                "message": log.get("message"),
                "security_event": log.get("security", {}),
            })
    return auth_failures


def find_ips_with_failed_requests(
    logs: list[dict[str, Any]], threshold: int = 10
) -> dict[str, dict[str, Any]]:
    """Find unique IPs with more than threshold failed requests."""
    ip_failures: dict[str, list[dict[str, Any]]] = defaultdict(list)
    
    for log in logs:
        http = log.get("http", {})
        status_code = http.get("status_code", 0)
        if status_code >= 400:
            client_ip = log.get("client", {}).get("ip")
            if client_ip:
                ip_failures[client_ip].append({
                    "timestamp": log.get("@timestamp"),
                    "status_code": status_code,
                    "endpoint": http.get("endpoint"),
                    "message": log.get("message"),
                })
    
    suspicious_ips = {}
    for ip, failures in ip_failures.items():
        if len(failures) > threshold:
            suspicious_ips[ip] = {
                "total_failures": len(failures),
                "status_codes": list(set(f["status_code"] for f in failures)),
                "endpoints": list(set(f["endpoint"] for f in failures if f["endpoint"])),
                "sample_requests": failures[:5],
            }
    
    return suspicious_ips


def find_sql_xss_patterns(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find SQL injection and XSS patterns in request paths and payloads."""
    sql_patterns = [
        r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"(?i)\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"(?i)((\%27)|(\'))union",
        r"(?i)union.*select",
        r"(?i)select.*from",
        r"(?i)insert.*into",
        r"(?i)drop.*table",
        r"(?i)delete.*from",
        r"(?i)update.*set",
        r"(?i)' OR '1'='1",
        r"(?i)1=1",
        r"(?i)or 1=1",
    ]
    
    xss_patterns = [
        r"(?i)<script[^>]*>",
        r"(?i)</script>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=",
        r"(?i)<img[^>]+onerror",
        r"(?i)<svg[^>]+onload",
        r"(?i)alert\s*\(",
        r"(?i)document\.cookie",
        r"(?i)document\.location",
        r"(?i)eval\s*\(",
    ]
    
    suspicious_requests = []
    
    for log in logs:
        http = log.get("http", {})
        endpoint = http.get("endpoint", "")
        security = log.get("security", {})
        payload = security.get("payload", "")
        event_type = security.get("event_type", "")
        message = log.get("message", "")
        
        detected_patterns = []
        
        for pattern in sql_patterns:
            if re.search(pattern, endpoint) or re.search(pattern, payload):
                detected_patterns.append(("SQL_INJECTION", pattern))
                break
        
        for pattern in xss_patterns:
            if re.search(pattern, endpoint) or re.search(pattern, payload):
                detected_patterns.append(("XSS", pattern))
                break
        
        if event_type in ("SQL_INJECTION_ATTEMPT", "XSS_ATTEMPT"):
            detected_patterns.append((event_type, "security.event_type"))
        
        if "SQL injection" in message.lower():
            detected_patterns.append(("SQL_INJECTION", "message"))
        if "XSS" in message.upper():
            detected_patterns.append(("XSS", "message"))
        
        if detected_patterns:
            suspicious_requests.append({
                "timestamp": log.get("@timestamp"),
                "log_id": log.get("log_id"),
                "service": log.get("service"),
                "host": log.get("host"),
                "method": http.get("method"),
                "endpoint": endpoint,
                "status_code": http.get("status_code"),
                "client_ip": log.get("client", {}).get("ip"),
                "user_agent": log.get("client", {}).get("user_agent"),
                "payload": payload,
                "detected_patterns": detected_patterns,
                "security_event": security,
                "message": message,
            })
    
    return suspicious_requests


def generate_html_report(
    auth_failures: list[dict[str, Any]],
    suspicious_ips: dict[str, dict[str, Any]],
    sql_xss_patterns: list[dict[str, Any]],
    output_path: Path,
    log_files: list[str],
) -> None:
    """Generate an HTML security report."""
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #1976d2;
            margin-top: 30px;
            border-bottom: 2px solid #1976d2;
            padding-bottom: 5px;
        }}
        h3 {{
            color: #388e3c;
        }}
        .summary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }}
        .summary-card {{
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .summary-card .label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background-color: #37474f;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .status-401 {{
            background-color: #fff3e0;
            color: #e65100;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .status-403 {{
            background-color: #ffebee;
            color: #c62828;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .ip-card {{
            background: white;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #d32f2f;
        }}
        .ip-card h4 {{
            margin: 0 0 10px 0;
            color: #d32f2f;
        }}
        .pattern-tag {{
            display: inline-block;
            padding: 3px 10px;
            margin: 2px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .pattern-sql {{
            background-color: #ffcdd2;
            color: #b71c1c;
        }}
        .pattern-xss {{
            background-color: #f3e5f5;
            color: #6a1b9a;
        }}
        .code {{
            font-family: 'Courier New', monospace;
            background-color: #263238;
            color: #80cbc4;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .meta-info {{
            color: #757575;
            font-size: 0.9em;
            margin-bottom: 20px;
        }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .warning {{
            background-color: #fff8e1;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }}
        .critical {{
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }}
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    
    <div class="meta-info">
        <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}<br>
        <strong>Log Files Analyzed:</strong> {', '.join(log_files)}
    </div>
    
    <div class="summary">
        <h2 style="color: white; border: none; margin-top: 0;">Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <div class="number">{len(auth_failures)}</div>
                <div class="label">401/403 Auth Failures</div>
            </div>
            <div class="summary-card">
                <div class="number">{len(suspicious_ips)}</div>
                <div class="label">Suspicious IPs (&gt;10 failures)</div>
            </div>
            <div class="summary-card">
                <div class="number">{len(sql_xss_patterns)}</div>
                <div class="label">SQL/XSS Patterns Detected</div>
            </div>
        </div>
    </div>
"""
    
    html += """
    <div class="section">
        <h2>1. Authentication Failures (401/403)</h2>
"""
    
    if auth_failures:
        html += f"""
        <div class="warning">
            <strong>Finding:</strong> {len(auth_failures)} authentication failure(s) detected. 
            These may indicate unauthorized access attempts or misconfigured credentials.
        </div>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Status</th>
                <th>Service</th>
                <th>Endpoint</th>
                <th>Client IP</th>
                <th>Message</th>
            </tr>
"""
        for entry in auth_failures:
            status_class = f"status-{entry['status_code']}"
            html += f"""
            <tr>
                <td>{entry['timestamp']}</td>
                <td><span class="{status_class}">{entry['status_code']}</span></td>
                <td>{entry['service']}</td>
                <td><code>{entry['endpoint']}</code></td>
                <td><code>{entry['client_ip']}</code></td>
                <td>{entry['message']}</td>
            </tr>
"""
        html += "</table>"
    else:
        html += "<p>No 401/403 authentication failures detected.</p>"
    
    html += "</div>"
    
    html += """
    <div class="section">
        <h2>2. Suspicious IPs (>10 Failed Requests)</h2>
"""
    
    if suspicious_ips:
        html += f"""
        <div class="critical">
            <strong>Critical Finding:</strong> {len(suspicious_ips)} IP address(es) with more than 10 failed requests. 
            These IPs may be conducting brute force attacks or automated scanning.
        </div>
"""
        sorted_ips = sorted(
            suspicious_ips.items(), 
            key=lambda x: x[1]['total_failures'], 
            reverse=True
        )
        for ip, data in sorted_ips:
            html += f"""
        <div class="ip-card">
            <h4>{ip}</h4>
            <p><strong>Total Failed Requests:</strong> {data['total_failures']}</p>
            <p><strong>Status Codes:</strong> {', '.join(map(str, data['status_codes']))}</p>
            <p><strong>Targeted Endpoints:</strong></p>
            <ul>
"""
            for endpoint in data['endpoints'][:10]:
                html += f"<li><code>{endpoint}</code></li>"
            html += """
            </ul>
        </div>
"""
    else:
        html += "<p>No IPs with more than 10 failed requests detected.</p>"
    
    html += "</div>"
    
    html += """
    <div class="section">
        <h2>3. SQL Injection / XSS Patterns</h2>
"""
    
    if sql_xss_patterns:
        sql_count = sum(1 for p in sql_xss_patterns if any("SQL" in d[0] for d in p['detected_patterns']))
        xss_count = sum(1 for p in sql_xss_patterns if any("XSS" in d[0] for d in p['detected_patterns']))
        
        html += f"""
        <div class="critical">
            <strong>Critical Finding:</strong> {len(sql_xss_patterns)} potential injection attack(s) detected.
            SQL Injection attempts: {sql_count}, XSS attempts: {xss_count}
        </div>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>Service</th>
                <th>Endpoint</th>
                <th>Client IP</th>
                <th>Payload/Details</th>
            </tr>
"""
        for entry in sql_xss_patterns:
            pattern_types = set(p[0] for p in entry['detected_patterns'])
            pattern_tags = ""
            for pt in pattern_types:
                if "SQL" in pt:
                    pattern_tags += '<span class="pattern-tag pattern-sql">SQL Injection</span>'
                if "XSS" in pt:
                    pattern_tags += '<span class="pattern-tag pattern-xss">XSS</span>'
            
            payload_display = entry['payload'] if entry['payload'] else entry['message']
            html += f"""
            <tr>
                <td>{entry['timestamp']}</td>
                <td>{pattern_tags}</td>
                <td>{entry['service']}</td>
                <td><code>{entry['endpoint']}</code></td>
                <td><code>{entry['client_ip']}</code></td>
                <td>{payload_display[:100]}{'...' if len(payload_display) > 100 else ''}</td>
            </tr>
"""
        html += "</table>"
    else:
        html += "<p>No SQL injection or XSS patterns detected.</p>"
    
    html += """
    </div>
    
    <div class="section">
        <h2>Recommendations</h2>
        <ol>
"""
    
    if auth_failures:
        html += """
            <li><strong>Review Authentication Failures:</strong> Investigate the source IPs and determine if they represent legitimate users with credential issues or potential attackers.</li>
"""
    
    if suspicious_ips:
        html += """
            <li><strong>Block Suspicious IPs:</strong> Consider implementing IP-based rate limiting or blocking for the identified suspicious IP addresses.</li>
"""
    
    if sql_xss_patterns:
        html += """
            <li><strong>Strengthen Input Validation:</strong> Ensure all user inputs are properly sanitized and parameterized queries are used for database operations.</li>
            <li><strong>Implement WAF Rules:</strong> Deploy Web Application Firewall rules to detect and block common injection patterns.</li>
"""
    
    html += """
            <li><strong>Enable Enhanced Logging:</strong> Ensure detailed logging is enabled for security events to aid in forensic analysis.</li>
            <li><strong>Regular Security Audits:</strong> Conduct periodic security assessments to identify and remediate vulnerabilities.</li>
        </ol>
    </div>
    
    <footer style="text-align: center; color: #757575; margin-top: 30px; padding: 20px;">
        <p>Generated by Elastic Logs Security Analyzer</p>
    </footer>
</body>
</html>
"""
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)


def main() -> None:
    """Main entry point for security report generation."""
    repo_root = Path(__file__).parent.parent
    
    log_files = [
        repo_root / "logs" / "elastic_logs_28_11_25.json",
        repo_root / "logs_to_be" / "elastic_logs_29_11_25.json",
        repo_root / "logs_to_be" / "elastic_logs_30_11_25.json",
    ]
    
    existing_files = [f for f in log_files if f.exists()]
    print(f"Loading logs from {len(existing_files)} file(s)...")
    
    logs = load_logs(existing_files)
    print(f"Loaded {len(logs)} log entries")
    
    print("Analyzing authentication failures (401/403)...")
    auth_failures = find_auth_failures(logs)
    print(f"Found {len(auth_failures)} authentication failures")
    
    print("Analyzing IPs with failed requests...")
    suspicious_ips = find_ips_with_failed_requests(logs, threshold=10)
    print(f"Found {len(suspicious_ips)} suspicious IPs with >10 failures")
    
    print("Analyzing SQL/XSS patterns...")
    sql_xss_patterns = find_sql_xss_patterns(logs)
    print(f"Found {len(sql_xss_patterns)} potential SQL/XSS attacks")
    
    output_path = repo_root / "analysis" / "security_report_20251201_204709.html"
    print(f"Generating HTML report at {output_path}...")
    
    generate_html_report(
        auth_failures=auth_failures,
        suspicious_ips=suspicious_ips,
        sql_xss_patterns=sql_xss_patterns,
        output_path=output_path,
        log_files=[f.name for f in existing_files],
    )
    
    print(f"Report generated successfully: {output_path}")


if __name__ == "__main__":
    main()
