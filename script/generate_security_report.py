#!/usr/bin/env python3
"""
Security Report Generator

Analyzes Elasticsearch-format logs for security issues and generates an HTML report.
Detects: 401/403 status codes, IPs with >10 failed requests, SQL/XSS patterns.
"""

import json
import re
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load and parse JSON log file."""
    with open(log_file, 'r') as f:
        return json.load(f)


def find_auth_failures(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Find all entries with status_code 401 or 403."""
    auth_failures = []
    for log in logs:
        status_code = log.get('http', {}).get('status_code')
        if status_code in [401, 403]:
            auth_failures.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'status_code': status_code,
                'service': log.get('service'),
                'endpoint': log.get('http', {}).get('endpoint'),
                'method': log.get('http', {}).get('method'),
                'ip': log.get('client', {}).get('ip'),
                'user_agent': log.get('client', {}).get('user_agent'),
                'message': log.get('message'),
                'event_type': log.get('security', {}).get('event_type', 'N/A'),
            })
    return auth_failures


def find_ips_with_failed_requests(
    logs: list[dict[str, Any]], threshold: int = 10
) -> list[tuple[str, int]]:
    """Find unique IPs with more than threshold failed requests (401, 403, 500)."""
    failed_ips: Counter[str] = Counter()
    for log in logs:
        status_code = log.get('http', {}).get('status_code')
        if status_code in [401, 403, 500]:
            ip = log.get('client', {}).get('ip')
            if ip:
                failed_ips[ip] += 1
    return [(ip, count) for ip, count in failed_ips.most_common() if count > threshold]


def find_sql_xss_patterns(logs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Detect SQL injection and XSS patterns in request_path/endpoint and payloads."""
    sql_patterns = [
        r"'\s*OR\s*'",
        r'UNION\s+SELECT',
        r'DROP\s+TABLE',
        r'INSERT\s+INTO',
        r'DELETE\s+FROM',
        r';\s*SELECT',
        r'1\s*=\s*1',
        r'--\s*$',
    ]

    xss_patterns = [
        r'<script',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
        r'onclick\s*=',
        r'<img[^>]*onerror',
        r'alert\s*\(',
        r'document\.cookie',
    ]

    sql_findings: list[dict[str, Any]] = []
    xss_findings: list[dict[str, Any]] = []
    seen_sql: set[str] = set()
    seen_xss: set[str] = set()

    for log in logs:
        log_id = log.get('log_id', '')
        endpoint = log.get('http', {}).get('endpoint', '')
        security = log.get('security', {})
        payload = security.get('payload', '')
        event_type = security.get('event_type', '')
        search_text = f"{endpoint} {payload}"

        finding = {
            'log_id': log_id,
            'timestamp': log.get('@timestamp'),
            'endpoint': endpoint,
            'payload': payload,
            'event_type': event_type,
            'ip': log.get('client', {}).get('ip'),
            'user_agent': log.get('client', {}).get('user_agent'),
            'service': log.get('service'),
            'status_code': log.get('http', {}).get('status_code'),
        }

        is_sql = False
        for pattern in sql_patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                is_sql = True
                break
        if 'SQL_INJECTION' in event_type:
            is_sql = True

        if is_sql and log_id not in seen_sql:
            sql_findings.append(finding)
            seen_sql.add(log_id)

        is_xss = False
        for pattern in xss_patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                is_xss = True
                break
        if 'XSS' in event_type:
            is_xss = True

        if is_xss and log_id not in seen_xss:
            xss_findings.append(finding)
            seen_xss.add(log_id)

    return {'sql_injection': sql_findings, 'xss': xss_findings}


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#39;')
    )


def generate_html_report(
    auth_failures: list[dict[str, Any]],
    high_fail_ips: list[tuple[str, int]],
    attack_patterns: dict[str, list[dict[str, Any]]],
    log_file: str,
    total_logs: int,
) -> str:
    """Generate HTML security report."""
    report_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        header h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
        }}
        .meta-info {{
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            font-size: 0.9rem;
            opacity: 0.9;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .card h3 {{
            font-size: 0.9rem;
            text-transform: uppercase;
            color: #666;
            margin-bottom: 10px;
        }}
        .card .value {{
            font-size: 2.5rem;
            font-weight: bold;
        }}
        .card.critical .value {{ color: #dc3545; }}
        .card.warning .value {{ color: #ffc107; }}
        .card.info .value {{ color: #17a2b8; }}
        section {{
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        section h2 {{
            color: #1a1a2e;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #555;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .status-401, .status-403 {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .status-401 {{
            background: #fff3cd;
            color: #856404;
        }}
        .status-403 {{
            background: #f8d7da;
            color: #721c24;
        }}
        .attack-type {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .sql-injection {{
            background: #f8d7da;
            color: #721c24;
        }}
        .xss {{
            background: #fff3cd;
            color: #856404;
        }}
        .payload {{
            font-family: 'Courier New', monospace;
            background: #f8f9fa;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            word-break: break-all;
        }}
        .ip-address {{
            font-family: 'Courier New', monospace;
            color: #0066cc;
        }}
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-style: italic;
        }}
        .severity-high {{
            border-left: 4px solid #dc3545;
        }}
        .severity-medium {{
            border-left: 4px solid #ffc107;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Analysis Report</h1>
            <div class="meta-info">
                <span>Generated: {report_time}</span>
                <span>Log File: {escape_html(log_file)}</span>
                <span>Total Entries Analyzed: {total_logs}</span>
            </div>
        </header>

        <div class="summary-cards">
            <div class="card critical">
                <h3>Authentication Failures (401/403)</h3>
                <div class="value">{len(auth_failures)}</div>
            </div>
            <div class="card warning">
                <h3>IPs with &gt;10 Failed Requests</h3>
                <div class="value">{len(high_fail_ips)}</div>
            </div>
            <div class="card critical">
                <h3>SQL Injection Attempts</h3>
                <div class="value">{len(attack_patterns['sql_injection'])}</div>
            </div>
            <div class="card warning">
                <h3>XSS Attempts</h3>
                <div class="value">{len(attack_patterns['xss'])}</div>
            </div>
        </div>

        <section class="severity-high">
            <h2>Authentication Failures (Status 401/403)</h2>
"""

    if auth_failures:
        html += """            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Log ID</th>
                        <th>Status</th>
                        <th>Service</th>
                        <th>Endpoint</th>
                        <th>Client IP</th>
                        <th>Event Type</th>
                    </tr>
                </thead>
                <tbody>
"""
        for entry in auth_failures:
            status_class = f"status-{entry['status_code']}"
            html += f"""                    <tr>
                        <td>{escape_html(entry['timestamp'])}</td>
                        <td>{escape_html(entry['log_id'])}</td>
                        <td><span class="{status_class}">{entry['status_code']}</span></td>
                        <td>{escape_html(entry['service'])}</td>
                        <td>{escape_html(entry['endpoint'])}</td>
                        <td class="ip-address">{escape_html(entry['ip'])}</td>
                        <td>{escape_html(entry['event_type'])}</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
"""
    else:
        html += """            <div class="no-data">No authentication failures detected.</div>
"""

    html += """        </section>

        <section class="severity-medium">
            <h2>IPs with &gt;10 Failed Requests</h2>
"""

    if high_fail_ips:
        html += """            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Failed Request Count</th>
                    </tr>
                </thead>
                <tbody>
"""
        for ip, count in high_fail_ips:
            html += f"""                    <tr>
                        <td class="ip-address">{escape_html(ip)}</td>
                        <td>{count}</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
"""
    else:
        html += """            <div class="no-data">No IPs found with more than 10 failed requests.</div>
"""

    html += """        </section>

        <section class="severity-high">
            <h2>SQL Injection Attempts</h2>
"""

    if attack_patterns['sql_injection']:
        html += """            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Log ID</th>
                        <th>Endpoint</th>
                        <th>Payload</th>
                        <th>Client IP</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        for entry in attack_patterns['sql_injection']:
            html += f"""                    <tr>
                        <td>{escape_html(entry['timestamp'])}</td>
                        <td>{escape_html(entry['log_id'])}</td>
                        <td>{escape_html(entry['endpoint'])}</td>
                        <td><span class="payload">{escape_html(entry['payload'])}</span></td>
                        <td class="ip-address">{escape_html(entry['ip'])}</td>
                        <td>{entry['status_code']}</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
"""
    else:
        html += """            <div class="no-data">No SQL injection attempts detected.</div>
"""

    html += """        </section>

        <section class="severity-medium">
            <h2>XSS Attempts</h2>
"""

    if attack_patterns['xss']:
        html += """            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Log ID</th>
                        <th>Endpoint</th>
                        <th>Payload</th>
                        <th>Client IP</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"""
        for entry in attack_patterns['xss']:
            html += f"""                    <tr>
                        <td>{escape_html(entry['timestamp'])}</td>
                        <td>{escape_html(entry['log_id'])}</td>
                        <td>{escape_html(entry['endpoint'])}</td>
                        <td><span class="payload">{escape_html(entry['payload'])}</span></td>
                        <td class="ip-address">{escape_html(entry['ip'])}</td>
                        <td>{entry['status_code']}</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
"""
    else:
        html += """            <div class="no-data">No XSS attempts detected.</div>
"""

    html += """        </section>
    </div>
</body>
</html>
"""
    return html


def main() -> None:
    """Main entry point for security report generation."""
    parser = argparse.ArgumentParser(
        description='Generate security analysis report from Elasticsearch logs'
    )
    parser.add_argument(
        '--log-file',
        required=True,
        help='Path to the JSON log file'
    )
    parser.add_argument(
        '--output-file',
        required=True,
        help='Path for the output HTML report'
    )
    parser.add_argument(
        '--failed-request-threshold',
        type=int,
        default=10,
        help='Threshold for flagging IPs with failed requests (default: 10)'
    )

    args = parser.parse_args()

    print(f"Loading logs from {args.log_file}...")
    logs = load_logs(args.log_file)
    print(f"Loaded {len(logs)} log entries")

    print("Analyzing authentication failures (401/403)...")
    auth_failures = find_auth_failures(logs)
    print(f"Found {len(auth_failures)} authentication failures")

    print(f"Finding IPs with >{args.failed_request_threshold} failed requests...")
    high_fail_ips = find_ips_with_failed_requests(logs, args.failed_request_threshold)
    print(f"Found {len(high_fail_ips)} IPs exceeding threshold")

    print("Detecting SQL injection and XSS patterns...")
    attack_patterns = find_sql_xss_patterns(logs)
    print(f"Found {len(attack_patterns['sql_injection'])} SQL injection attempts")
    print(f"Found {len(attack_patterns['xss'])} XSS attempts")

    print(f"Generating HTML report at {args.output_file}...")
    html_report = generate_html_report(
        auth_failures,
        high_fail_ips,
        attack_patterns,
        args.log_file,
        len(logs)
    )

    output_path = Path(args.output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html_report)

    print(f"Security report generated successfully: {args.output_file}")


if __name__ == '__main__':
    main()
