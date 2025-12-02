#!/usr/bin/env python3
"""Security analysis script for elastic logs.

Analyzes log files for:
- Status code 401/403 entries (authentication/authorization failures)
- Unique IPs with >10 failed requests
- SQL injection patterns in request paths
- XSS patterns in request paths
"""

import json
import re
import argparse
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


SQL_INJECTION_PATTERNS = [
    r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"(?i)((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"(?i)\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"(?i)((\%27)|(\'))union",
    r"(?i)union.*select",
    r"(?i)select.*from",
    r"(?i)insert.*into",
    r"(?i)delete.*from",
    r"(?i)drop.*table",
    r"(?i)update.*set",
    r"(?i)exec(\s|\+)+(s|x)p\w+",
    r"(?i)1\s*=\s*1",
    r"(?i)1'\s*or\s*'1'\s*=\s*'1",
    r"(?i)' or '1'='1",
    r"(?i)admin'--",
    r"(?i)or\s+1=1",
    r"(?i)'\s*or\s*''='",
]

XSS_PATTERNS = [
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
    r"(?i)<iframe",
    r"(?i)expression\s*\(",
    r"(?i)vbscript:",
    r"(?i)data:text/html",
]


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load and parse JSON log file."""
    with open(log_file, "r") as f:
        return json.load(f)


def find_auth_failures(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find all entries with status_code 401 or 403."""
    auth_failures = []
    for log in logs:
        http_info = log.get("http", {})
        status_code = http_info.get("status_code")
        if status_code in [401, 403]:
            auth_failures.append(log)
    return auth_failures


def find_ips_with_failed_requests(
    logs: list[dict[str, Any]], threshold: int = 10
) -> dict[str, list[dict[str, Any]]]:
    """Find unique IPs with more than threshold failed requests."""
    ip_failures: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for log in logs:
        http_info = log.get("http", {})
        status_code = http_info.get("status_code", 0)
        if status_code >= 400:
            client_ip = log.get("client", {}).get("ip", "unknown")
            ip_failures[client_ip].append(log)

    return {ip: entries for ip, entries in ip_failures.items() if len(entries) > threshold}


def detect_sql_injection(endpoint: str) -> list[str]:
    """Detect SQL injection patterns in endpoint."""
    matches = []
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, endpoint):
            matches.append(pattern)
    return matches


def detect_xss(endpoint: str) -> list[str]:
    """Detect XSS patterns in endpoint."""
    matches = []
    for pattern in XSS_PATTERNS:
        if re.search(pattern, endpoint):
            matches.append(pattern)
    return matches


def find_injection_attempts(
    logs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Find SQL injection and XSS attempts in request paths."""
    sql_injections = []
    xss_attempts = []

    for log in logs:
        http_info = log.get("http", {})
        endpoint = http_info.get("endpoint", "")
        message = log.get("message", "")
        security_info = log.get("security", {})
        security_payload = security_info.get("payload", "")

        check_strings = [endpoint, message, security_payload]

        for check_str in check_strings:
            if check_str:
                sql_matches = detect_sql_injection(check_str)
                if sql_matches:
                    sql_injections.append(
                        {"log": log, "matches": sql_matches, "source": check_str}
                    )
                    break

        for check_str in check_strings:
            if check_str:
                xss_matches = detect_xss(check_str)
                if xss_matches:
                    xss_attempts.append(
                        {"log": log, "matches": xss_matches, "source": check_str}
                    )
                    break

        event_type = security_info.get("event_type", "")
        if "SQL_INJECTION" in event_type and not any(
            s["log"]["log_id"] == log["log_id"] for s in sql_injections
        ):
            sql_injections.append(
                {"log": log, "matches": ["event_type: SQL_INJECTION"], "source": event_type}
            )
        if "XSS" in event_type and not any(
            x["log"]["log_id"] == log["log_id"] for x in xss_attempts
        ):
            xss_attempts.append(
                {"log": log, "matches": ["event_type: XSS"], "source": event_type}
            )

    return sql_injections, xss_attempts


def generate_html_report(
    auth_failures: list[dict[str, Any]],
    ips_with_failures: dict[str, list[dict[str, Any]]],
    sql_injections: list[dict[str, Any]],
    xss_attempts: list[dict[str, Any]],
    log_file: str,
    output_file: str,
) -> None:
    """Generate HTML security report."""
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
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
            border-left: 4px solid #1976d2;
            padding-left: 10px;
        }}
        h3 {{
            color: #388e3c;
        }}
        .summary-box {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px 25px;
            background: #e3f2fd;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #1976d2;
        }}
        .stat-label {{
            font-size: 0.9em;
            color: #666;
        }}
        .critical {{
            background: #ffebee;
        }}
        .critical .stat-number {{
            color: #d32f2f;
        }}
        .warning {{
            background: #fff3e0;
        }}
        .warning .stat-number {{
            color: #f57c00;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #1976d2;
            color: white;
        }}
        tr:hover {{
            background: #f5f5f5;
        }}
        .code {{
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .badge-401 {{
            background: #ffcdd2;
            color: #c62828;
        }}
        .badge-403 {{
            background: #ffe0b2;
            color: #e65100;
        }}
        .badge-sql {{
            background: #f3e5f5;
            color: #7b1fa2;
        }}
        .badge-xss {{
            background: #e8f5e9;
            color: #2e7d32;
        }}
        .ip-card {{
            background: white;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .ip-header {{
            font-weight: bold;
            color: #d32f2f;
            font-size: 1.1em;
        }}
        .meta {{
            color: #666;
            font-size: 0.9em;
            margin-top: 20px;
        }}
        .no-issues {{
            color: #388e3c;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    
    <div class="meta">
        <strong>Log File:</strong> {log_file}<br>
        <strong>Report Generated:</strong> {report_time}
    </div>

    <div class="summary-box">
        <h2 style="margin-top: 0;">Executive Summary</h2>
        <div class="stat critical">
            <div class="stat-number">{len(auth_failures)}</div>
            <div class="stat-label">Auth Failures (401/403)</div>
        </div>
        <div class="stat warning">
            <div class="stat-number">{len(ips_with_failures)}</div>
            <div class="stat-label">Suspicious IPs (&gt;10 failures)</div>
        </div>
        <div class="stat critical">
            <div class="stat-number">{len(sql_injections)}</div>
            <div class="stat-label">SQL Injection Attempts</div>
        </div>
        <div class="stat warning">
            <div class="stat-number">{len(xss_attempts)}</div>
            <div class="stat-label">XSS Attempts</div>
        </div>
    </div>

    <h2>1. Authentication/Authorization Failures (401/403)</h2>
"""

    if auth_failures:
        html_content += """
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Status</th>
                <th>Service</th>
                <th>Endpoint</th>
                <th>Client IP</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>
"""
        for log in auth_failures:
            timestamp = log.get("@timestamp", "N/A")
            status = log.get("http", {}).get("status_code", "N/A")
            service = log.get("service", "N/A")
            endpoint = log.get("http", {}).get("endpoint", "N/A")
            client_ip = log.get("client", {}).get("ip", "N/A")
            message = log.get("message", "N/A")
            badge_class = "badge-401" if status == 401 else "badge-403"

            html_content += f"""
            <tr>
                <td><span class="code">{timestamp}</span></td>
                <td><span class="badge {badge_class}">{status}</span></td>
                <td>{service}</td>
                <td><span class="code">{endpoint}</span></td>
                <td><span class="code">{client_ip}</span></td>
                <td>{message}</td>
            </tr>
"""
        html_content += """
        </tbody>
    </table>
"""
    else:
        html_content += '<p class="no-issues">No authentication/authorization failures found.</p>'

    html_content += """
    <h2>2. IPs with &gt;10 Failed Requests</h2>
"""

    if ips_with_failures:
        for ip, entries in sorted(
            ips_with_failures.items(), key=lambda x: len(x[1]), reverse=True
        ):
            html_content += f"""
    <div class="ip-card">
        <div class="ip-header">{ip} - {len(entries)} failed requests</div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>Endpoint</th>
                    <th>Service</th>
                </tr>
            </thead>
            <tbody>
"""
            for entry in entries[:20]:
                timestamp = entry.get("@timestamp", "N/A")
                status = entry.get("http", {}).get("status_code", "N/A")
                endpoint = entry.get("http", {}).get("endpoint", "N/A")
                service = entry.get("service", "N/A")
                html_content += f"""
                <tr>
                    <td><span class="code">{timestamp}</span></td>
                    <td>{status}</td>
                    <td><span class="code">{endpoint}</span></td>
                    <td>{service}</td>
                </tr>
"""
            if len(entries) > 20:
                html_content += f"""
                <tr>
                    <td colspan="4"><em>... and {len(entries) - 20} more entries</em></td>
                </tr>
"""
            html_content += """
            </tbody>
        </table>
    </div>
"""
    else:
        html_content += '<p class="no-issues">No IPs found with more than 10 failed requests.</p>'

    html_content += """
    <h2>3. SQL Injection Patterns Detected</h2>
"""

    if sql_injections:
        html_content += """
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Client IP</th>
                <th>Endpoint</th>
                <th>Detected Pattern Source</th>
                <th>Service</th>
            </tr>
        </thead>
        <tbody>
"""
        for item in sql_injections:
            log = item["log"]
            source = item["source"]
            timestamp = log.get("@timestamp", "N/A")
            client_ip = log.get("client", {}).get("ip", "N/A")
            endpoint = log.get("http", {}).get("endpoint", "N/A")
            service = log.get("service", "N/A")

            html_content += f"""
            <tr>
                <td><span class="code">{timestamp}</span></td>
                <td><span class="code">{client_ip}</span></td>
                <td><span class="code">{endpoint}</span></td>
                <td><span class="badge badge-sql">{source[:50]}...</span></td>
                <td>{service}</td>
            </tr>
"""
        html_content += """
        </tbody>
    </table>
"""
    else:
        html_content += '<p class="no-issues">No SQL injection patterns detected in request paths.</p>'

    html_content += """
    <h2>4. XSS Patterns Detected</h2>
"""

    if xss_attempts:
        html_content += """
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Client IP</th>
                <th>Endpoint</th>
                <th>Detected Pattern Source</th>
                <th>Service</th>
            </tr>
        </thead>
        <tbody>
"""
        for item in xss_attempts:
            log = item["log"]
            source = item["source"]
            timestamp = log.get("@timestamp", "N/A")
            client_ip = log.get("client", {}).get("ip", "N/A")
            endpoint = log.get("http", {}).get("endpoint", "N/A")
            service = log.get("service", "N/A")

            html_content += f"""
            <tr>
                <td><span class="code">{timestamp}</span></td>
                <td><span class="code">{client_ip}</span></td>
                <td><span class="code">{endpoint}</span></td>
                <td><span class="badge badge-xss">{source[:50]}...</span></td>
                <td>{service}</td>
            </tr>
"""
        html_content += """
        </tbody>
    </table>
"""
    else:
        html_content += '<p class="no-issues">No XSS patterns detected in request paths.</p>'

    html_content += """
</body>
</html>
"""

    with open(output_file, "w") as f:
        f.write(html_content)


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Analyze elastic logs for security issues")
    parser.add_argument("--log-file", required=True, help="Path to the log file")
    parser.add_argument("--output-file", required=True, help="Path to output HTML report")
    args = parser.parse_args()

    print(f"Loading logs from {args.log_file}...")
    logs = load_logs(args.log_file)
    print(f"Loaded {len(logs)} log entries")

    print("Analyzing authentication failures (401/403)...")
    auth_failures = find_auth_failures(logs)
    print(f"Found {len(auth_failures)} authentication failures")

    print("Finding IPs with >10 failed requests...")
    ips_with_failures = find_ips_with_failed_requests(logs, threshold=10)
    print(f"Found {len(ips_with_failures)} IPs with >10 failed requests")

    print("Detecting SQL injection and XSS patterns...")
    sql_injections, xss_attempts = find_injection_attempts(logs)
    print(f"Found {len(sql_injections)} SQL injection attempts")
    print(f"Found {len(xss_attempts)} XSS attempts")

    print(f"Generating HTML report: {args.output_file}")
    generate_html_report(
        auth_failures,
        ips_with_failures,
        sql_injections,
        xss_attempts,
        args.log_file,
        args.output_file,
    )
    print("Report generated successfully!")


if __name__ == "__main__":
    main()
