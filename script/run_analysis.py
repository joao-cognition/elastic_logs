#!/usr/bin/env python3
"""
Comprehensive Elastic Logs Analysis Script.

This script analyzes Elastic logs for error patterns, security issues,
and performance anomalies, generating detailed HTML reports.
"""

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """
    Load and parse JSON log file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entry dictionaries.
    """
    with open(log_file, 'r') as f:
        return json.load(f)


def get_html_header(title: str) -> str:
    """
    Generate HTML header with styling.

    Args:
        title: Page title.

    Returns:
        HTML header string.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #1a1a2e;
            border-bottom: 3px solid #4a90d9;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #16213e;
            margin-top: 30px;
            border-left: 4px solid #4a90d9;
            padding-left: 10px;
        }}
        h3 {{
            color: #0f3460;
        }}
        .summary-box {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .metric-card {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #4a90d9;
        }}
        .metric-label {{
            color: #666;
            font-size: 0.9em;
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
            background-color: #4a90d9;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-critical {{
            background-color: #ff4757;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: bold;
        }}
        .severity-high {{
            background-color: #ff6b35;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
        }}
        .severity-medium {{
            background-color: #ffa502;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
        }}
        .severity-low {{
            background-color: #2ed573;
            color: white;
            padding: 3px 8px;
            border-radius: 4px;
        }}
        .recommendation {{
            background: #e8f4f8;
            border-left: 4px solid #4a90d9;
            padding: 15px;
            margin: 10px 0;
        }}
        .warning {{
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
        }}
        .error-box {{
            background: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 10px 0;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        pre {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
"""


def get_html_footer() -> str:
    """
    Generate HTML footer.

    Returns:
        HTML footer string.
    """
    return """
</body>
</html>
"""


def analyze_errors(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Perform comprehensive error pattern analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing error analysis results.
    """
    error_logs = [log for log in logs if log.get('level') == 'ERROR']
    
    status_code_counts: Counter = Counter()
    service_counts: Counter = Counter()
    message_counts: Counter = Counter()
    endpoint_errors: Counter = Counter()
    error_timeline: defaultdict = defaultdict(list)
    error_details: list = []
    
    for log in error_logs:
        status_code = log.get('http', {}).get('status_code', 'Unknown')
        service = log.get('service', 'Unknown')
        message = log.get('message', 'Unknown')
        endpoint = log.get('http', {}).get('endpoint', 'Unknown')
        timestamp = log.get('@timestamp', '')
        
        status_code_counts[status_code] += 1
        service_counts[service] += 1
        message_counts[message] += 1
        endpoint_errors[endpoint] += 1
        
        hour = timestamp[:13] if timestamp else 'Unknown'
        error_timeline[hour].append(log)
        
        error_details.append({
            'timestamp': timestamp,
            'service': service,
            'status_code': status_code,
            'message': message,
            'endpoint': endpoint,
            'error_type': log.get('error', {}).get('type', 'Unknown'),
            'correlation_id': log.get('error', {}).get('correlation_id', 'N/A'),
            'stack_trace': log.get('error', {}).get('stack_trace', 'N/A')
        })
    
    root_causes = []
    for message, count in message_counts.most_common():
        if 'connection pool exhausted' in message.lower():
            root_causes.append({
                'issue': 'Database Connection Pool Exhaustion',
                'count': count,
                'cause': 'Too many concurrent database connections exceeding pool capacity',
                'remediation': [
                    'Increase connection pool size',
                    'Implement connection pooling with proper timeout settings',
                    'Add circuit breaker pattern for database calls',
                    'Review and optimize long-running queries'
                ]
            })
        elif 'out of memory' in message.lower():
            root_causes.append({
                'issue': 'Out of Memory Exception',
                'count': count,
                'cause': 'JVM heap exhaustion due to memory leaks or insufficient allocation',
                'remediation': [
                    'Increase JVM heap size (-Xmx)',
                    'Profile application for memory leaks',
                    'Implement proper garbage collection tuning',
                    'Add memory monitoring and alerts'
                ]
            })
        elif 'service unreachable' in message.lower() or 'connection refused' in message.lower():
            root_causes.append({
                'issue': 'Service Connectivity Issues',
                'count': count,
                'cause': 'Downstream services unavailable or network connectivity problems',
                'remediation': [
                    'Implement circuit breaker pattern',
                    'Add retry logic with exponential backoff',
                    'Set up health checks for dependent services',
                    'Configure proper timeouts'
                ]
            })
        elif 'timeout' in message.lower() or 'upstream' in message.lower():
            root_causes.append({
                'issue': 'Request Timeout / Upstream Failure',
                'count': count,
                'cause': 'Upstream services taking too long to respond or failing',
                'remediation': [
                    'Increase timeout thresholds appropriately',
                    'Implement async processing for long operations',
                    'Add caching layer to reduce upstream calls',
                    'Scale upstream services horizontally'
                ]
            })
    
    return {
        'total_errors': len(error_logs),
        'total_logs': len(logs),
        'error_rate': round(len(error_logs) / len(logs) * 100, 2) if logs else 0,
        'status_code_counts': dict(status_code_counts.most_common()),
        'service_counts': dict(service_counts.most_common()),
        'message_counts': dict(message_counts.most_common(10)),
        'endpoint_errors': dict(endpoint_errors.most_common(10)),
        'error_timeline': dict(error_timeline),
        'error_details': error_details,
        'root_causes': root_causes
    }


def generate_error_report(analysis: dict[str, Any], output_path: str) -> None:
    """
    Generate HTML error analysis report.

    Args:
        analysis: Error analysis results.
        output_path: Path to save the HTML report.
    """
    html = get_html_header("Error Pattern Analysis Report")
    
    html += f"""
    <h1>Error Pattern Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    
    <div class="summary-box">
        <h2 style="color: white; border: none; margin-top: 0;">Executive Summary</h2>
        <p>Analysis of {analysis['total_logs']} log entries identified {analysis['total_errors']} 
        errors, representing an error rate of {analysis['error_rate']}%.</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric-card">
            <div class="metric-value">{analysis['total_errors']}</div>
            <div class="metric-label">Total Errors</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{analysis['error_rate']}%</div>
            <div class="metric-label">Error Rate</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{len(analysis['service_counts'])}</div>
            <div class="metric-label">Affected Services</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{len(analysis['status_code_counts'])}</div>
            <div class="metric-label">Error Status Codes</div>
        </div>
    </div>
    
    <div class="section">
        <h2>1. Error Frequency by HTTP Status Code</h2>
        <table>
            <tr><th>Status Code</th><th>Count</th><th>Percentage</th><th>Description</th></tr>
    """
    
    status_descriptions = {
        500: 'Internal Server Error',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout'
    }
    
    for code, count in analysis['status_code_counts'].items():
        pct = round(count / analysis['total_errors'] * 100, 1) if analysis['total_errors'] else 0
        desc = status_descriptions.get(code, 'Unknown Error')
        html += f"<tr><td>{code}</td><td>{count}</td><td>{pct}%</td><td>{desc}</td></tr>"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>2. Errors by Service</h2>
        <table>
            <tr><th>Service</th><th>Error Count</th><th>Percentage</th></tr>
    """
    
    for service, count in analysis['service_counts'].items():
        pct = round(count / analysis['total_errors'] * 100, 1) if analysis['total_errors'] else 0
        html += f"<tr><td>{service}</td><td>{count}</td><td>{pct}%</td></tr>"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>3. Top Error Messages</h2>
        <table>
            <tr><th>Error Message</th><th>Count</th></tr>
    """
    
    for message, count in analysis['message_counts'].items():
        html += f"<tr><td>{message}</td><td>{count}</td></tr>"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>4. Endpoints with Highest Error Rates</h2>
        <table>
            <tr><th>Endpoint</th><th>Error Count</th></tr>
    """
    
    for endpoint, count in analysis['endpoint_errors'].items():
        html += f"<tr><td>{endpoint}</td><td>{count}</td></tr>"
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>5. Root Cause Analysis & Remediation</h2>
    """
    
    for rc in analysis['root_causes']:
        html += f"""
        <div class="error-box">
            <h3>{rc['issue']} ({rc['count']} occurrences)</h3>
            <p><strong>Root Cause:</strong> {rc['cause']}</p>
            <div class="recommendation">
                <strong>Recommended Actions:</strong>
                <ul>
        """
        for action in rc['remediation']:
            html += f"<li>{action}</li>"
        html += """
                </ul>
            </div>
        </div>
        """
    
    html += """
    </div>
    
    <div class="section">
        <h2>6. Error Timeline Analysis</h2>
        <table>
            <tr><th>Time Period</th><th>Error Count</th><th>Trend</th></tr>
    """
    
    timeline_counts = [(hour, len(errors)) for hour, errors in 
                       sorted(analysis['error_timeline'].items())]
    avg_errors = statistics.mean([c for _, c in timeline_counts]) if timeline_counts else 0
    
    for hour, count in timeline_counts:
        trend = "Spike" if count > avg_errors * 1.5 else "Normal"
        trend_class = "severity-high" if trend == "Spike" else "severity-low"
        html += f"""<tr><td>{hour}</td><td>{count}</td>
                    <td><span class="{trend_class}">{trend}</span></td></tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>7. Impact Assessment</h2>
        <div class="warning">
            <h3>Service Impact Summary</h3>
            <ul>
    """
    
    for service, count in list(analysis['service_counts'].items())[:5]:
        html += f"<li><strong>{service}</strong>: {count} errors - "
        html += "High impact on service reliability</li>"
    
    html += """
            </ul>
        </div>
        <div class="recommendation">
            <h3>Recommendations</h3>
            <ol>
                <li>Prioritize fixing database connection pool issues</li>
                <li>Implement circuit breakers for service-to-service calls</li>
                <li>Add comprehensive monitoring and alerting</li>
                <li>Review and optimize slow database queries</li>
                <li>Consider horizontal scaling for high-traffic services</li>
            </ol>
        </div>
    </div>
    """
    
    html += get_html_footer()
    
    with open(output_path, 'w') as f:
        f.write(html)


def analyze_security(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Perform comprehensive security issue detection.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing security analysis results.
    """
    auth_failures: list = []
    suspicious_ips: defaultdict = defaultdict(lambda: {'failures': 0, 'requests': 0, 'events': []})
    injection_attempts: list = []
    rate_limit_violations: list = []
    access_violations: list = []
    suspicious_user_agents: list = []
    
    known_attack_tools = ['sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'w3af', 'acunetix']
    known_malicious_ips = ['45.33.32.156', '185.220.101.1', '91.121.87.10']
    
    for log in logs:
        status_code = log.get('http', {}).get('status_code')
        ip = log.get('client', {}).get('ip', 'Unknown')
        user_agent = log.get('client', {}).get('user_agent', '')
        message = log.get('message', '')
        security_info = log.get('security', {})
        endpoint = log.get('http', {}).get('endpoint', '')
        timestamp = log.get('@timestamp', '')
        
        suspicious_ips[ip]['requests'] += 1
        
        if status_code in [401, 403]:
            auth_failures.append({
                'timestamp': timestamp,
                'ip': ip,
                'endpoint': endpoint,
                'status_code': status_code,
                'message': message,
                'user_agent': user_agent
            })
            suspicious_ips[ip]['failures'] += 1
            suspicious_ips[ip]['events'].append('auth_failure')
        
        if security_info.get('event_type') == 'SQL_INJECTION_ATTEMPT':
            injection_attempts.append({
                'timestamp': timestamp,
                'ip': ip,
                'endpoint': endpoint,
                'payload': security_info.get('payload', 'Unknown'),
                'user_agent': user_agent,
                'severity': 'Critical'
            })
            suspicious_ips[ip]['events'].append('sql_injection')
        
        if 'sql injection' in message.lower() or "' OR '" in str(security_info):
            if not any(i['timestamp'] == timestamp for i in injection_attempts):
                injection_attempts.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'endpoint': endpoint,
                    'payload': security_info.get('payload', 'Detected in message'),
                    'user_agent': user_agent,
                    'severity': 'Critical'
                })
        
        if status_code == 429 or security_info.get('event_type') == 'RATE_LIMIT_EXCEEDED':
            rate_limit_violations.append({
                'timestamp': timestamp,
                'ip': ip,
                'endpoint': endpoint,
                'requests_per_minute': security_info.get('requests_per_minute', 'Unknown'),
                'user_agent': user_agent
            })
            suspicious_ips[ip]['events'].append('rate_limit')
        
        if security_info.get('event_type') == 'UNAUTHORIZED_ACCESS':
            access_violations.append({
                'timestamp': timestamp,
                'ip': ip,
                'target_resource': security_info.get('target_resource', endpoint),
                'user_agent': user_agent
            })
            suspicious_ips[ip]['events'].append('unauthorized_access')
        
        ua_lower = user_agent.lower()
        for tool in known_attack_tools:
            if tool in ua_lower:
                suspicious_user_agents.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'user_agent': user_agent,
                    'tool_detected': tool,
                    'endpoint': endpoint
                })
                suspicious_ips[ip]['events'].append(f'attack_tool_{tool}')
                break
    
    high_risk_ips = []
    for ip, data in suspicious_ips.items():
        risk_score = 0
        risk_factors = []
        
        if data['failures'] > 10:
            risk_score += 30
            risk_factors.append(f"High failure rate ({data['failures']} failures)")
        elif data['failures'] > 5:
            risk_score += 15
            risk_factors.append(f"Moderate failure rate ({data['failures']} failures)")
        
        if 'sql_injection' in data['events']:
            risk_score += 50
            risk_factors.append("SQL injection attempt detected")
        
        if any('attack_tool' in e for e in data['events']):
            risk_score += 40
            risk_factors.append("Known attack tool detected")
        
        if 'rate_limit' in data['events']:
            risk_score += 20
            risk_factors.append("Rate limit exceeded")
        
        if ip in known_malicious_ips:
            risk_score += 30
            risk_factors.append("Known malicious IP")
        
        if risk_score > 0:
            high_risk_ips.append({
                'ip': ip,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'total_requests': data['requests'],
                'failures': data['failures'],
                'severity': 'Critical' if risk_score >= 50 else 
                           'High' if risk_score >= 30 else 'Medium'
            })
    
    high_risk_ips.sort(key=lambda x: x['risk_score'], reverse=True)
    
    findings = []
    
    if injection_attempts:
        findings.append({
            'category': 'SQL Injection Attempts',
            'severity': 'Critical',
            'count': len(injection_attempts),
            'description': 'Active SQL injection attacks detected',
            'recommendation': 'Block offending IPs immediately, review WAF rules'
        })
    
    sqlmap_count = len([ua for ua in suspicious_user_agents if ua['tool_detected'] == 'sqlmap'])
    if sqlmap_count > 0:
        findings.append({
            'category': 'Attack Tool Detection',
            'severity': 'Critical',
            'count': sqlmap_count,
            'description': f'SQLMap scanning tool detected ({sqlmap_count} requests)',
            'recommendation': 'Block IPs using attack tools, enhance rate limiting'
        })
    
    if len(auth_failures) > 20:
        findings.append({
            'category': 'Brute Force Indicators',
            'severity': 'High',
            'count': len(auth_failures),
            'description': 'High volume of authentication failures detected',
            'recommendation': 'Implement account lockout, add CAPTCHA'
        })
    
    if rate_limit_violations:
        findings.append({
            'category': 'Rate Limit Violations',
            'severity': 'Medium',
            'count': len(rate_limit_violations),
            'description': 'Multiple IPs exceeding rate limits',
            'recommendation': 'Review rate limit thresholds, consider IP blocking'
        })
    
    return {
        'total_logs': len(logs),
        'auth_failures': auth_failures,
        'auth_failure_count': len(auth_failures),
        'injection_attempts': injection_attempts,
        'rate_limit_violations': rate_limit_violations,
        'access_violations': access_violations,
        'suspicious_user_agents': suspicious_user_agents,
        'high_risk_ips': high_risk_ips[:20],
        'findings': findings,
        'unique_ips_with_failures': len([ip for ip, d in suspicious_ips.items() if d['failures'] > 0])
    }


def generate_security_report(analysis: dict[str, Any], output_path: str) -> None:
    """
    Generate HTML security analysis report.

    Args:
        analysis: Security analysis results.
        output_path: Path to save the HTML report.
    """
    html = get_html_header("Security Issue Detection Report")
    
    critical_count = len([f for f in analysis['findings'] if f['severity'] == 'Critical'])
    high_count = len([f for f in analysis['findings'] if f['severity'] == 'High'])
    
    html += f"""
    <h1>Security Issue Detection Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    
    <div class="summary-box">
        <h2 style="color: white; border: none; margin-top: 0;">Security Summary</h2>
        <p>Analysis identified {len(analysis['findings'])} security findings across 
        {analysis['total_logs']} log entries. 
        <strong>{critical_count} Critical</strong> and <strong>{high_count} High</strong> 
        severity issues require immediate attention.</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric-card">
            <div class="metric-value" style="color: #ff4757;">{critical_count}</div>
            <div class="metric-label">Critical Issues</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #ff6b35;">{high_count}</div>
            <div class="metric-label">High Severity</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{analysis['auth_failure_count']}</div>
            <div class="metric-label">Auth Failures</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{len(analysis['injection_attempts'])}</div>
            <div class="metric-label">Injection Attempts</div>
        </div>
    </div>
    
    <div class="section">
        <h2>1. Security Findings Summary</h2>
        <table>
            <tr><th>Category</th><th>Severity</th><th>Count</th>
                <th>Description</th><th>Recommendation</th></tr>
    """
    
    for finding in analysis['findings']:
        sev_class = f"severity-{finding['severity'].lower()}"
        html += f"""<tr>
            <td>{finding['category']}</td>
            <td><span class="{sev_class}">{finding['severity']}</span></td>
            <td>{finding['count']}</td>
            <td>{finding['description']}</td>
            <td>{finding['recommendation']}</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>2. SQL Injection Attempts</h2>
    """
    
    if analysis['injection_attempts']:
        html += """
        <div class="error-box">
            <strong>CRITICAL:</strong> Active SQL injection attacks detected!
        </div>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th>
                <th>Payload</th><th>User Agent</th></tr>
        """
        for attempt in analysis['injection_attempts'][:10]:
            html += f"""<tr>
                <td>{attempt['timestamp']}</td>
                <td>{attempt['ip']}</td>
                <td>{attempt['endpoint']}</td>
                <td><code>{attempt['payload']}</code></td>
                <td>{attempt['user_agent'][:50]}...</td>
            </tr>"""
        html += "</table>"
    else:
        html += "<p>No SQL injection attempts detected.</p>"
    
    html += """
    </div>
    
    <div class="section">
        <h2>3. High-Risk IP Addresses</h2>
        <table>
            <tr><th>IP Address</th><th>Risk Score</th><th>Severity</th>
                <th>Total Requests</th><th>Failures</th><th>Risk Factors</th></tr>
    """
    
    for ip_data in analysis['high_risk_ips'][:15]:
        sev_class = f"severity-{ip_data['severity'].lower()}"
        factors = "; ".join(ip_data['risk_factors'])
        html += f"""<tr>
            <td>{ip_data['ip']}</td>
            <td>{ip_data['risk_score']}</td>
            <td><span class="{sev_class}">{ip_data['severity']}</span></td>
            <td>{ip_data['total_requests']}</td>
            <td>{ip_data['failures']}</td>
            <td>{factors}</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>4. Attack Tool Detection</h2>
    """
    
    if analysis['suspicious_user_agents']:
        html += """
        <div class="warning">
            <strong>Warning:</strong> Known attack tools detected in user agents!
        </div>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Tool Detected</th>
                <th>Endpoint</th></tr>
        """
        for ua in analysis['suspicious_user_agents'][:10]:
            html += f"""<tr>
                <td>{ua['timestamp']}</td>
                <td>{ua['ip']}</td>
                <td><span class="severity-critical">{ua['tool_detected']}</span></td>
                <td>{ua['endpoint']}</td>
            </tr>"""
        html += "</table>"
    else:
        html += "<p>No known attack tools detected.</p>"
    
    html += """
    </div>
    
    <div class="section">
        <h2>5. Authentication Failures</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th>
                <th>Status Code</th><th>Message</th></tr>
    """
    
    for failure in analysis['auth_failures'][:15]:
        html += f"""<tr>
            <td>{failure['timestamp']}</td>
            <td>{failure['ip']}</td>
            <td>{failure['endpoint']}</td>
            <td>{failure['status_code']}</td>
            <td>{failure['message'][:50]}...</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>6. Rate Limit Violations</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th>
                <th>Requests/Min</th></tr>
    """
    
    for violation in analysis['rate_limit_violations'][:10]:
        html += f"""<tr>
            <td>{violation['timestamp']}</td>
            <td>{violation['ip']}</td>
            <td>{violation['endpoint']}</td>
            <td>{violation['requests_per_minute']}</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>7. Recommended Actions</h2>
        <div class="recommendation">
            <h3>Immediate Actions (Critical)</h3>
            <ol>
                <li>Block IPs identified with SQL injection attempts</li>
                <li>Review and strengthen WAF rules for injection patterns</li>
                <li>Implement IP-based rate limiting for suspicious sources</li>
            </ol>
        </div>
        <div class="recommendation">
            <h3>Short-term Actions (High Priority)</h3>
            <ol>
                <li>Implement account lockout after failed login attempts</li>
                <li>Add CAPTCHA for authentication endpoints</li>
                <li>Review access control policies for admin endpoints</li>
                <li>Enable detailed logging for security events</li>
            </ol>
        </div>
        <div class="recommendation">
            <h3>Long-term Improvements</h3>
            <ol>
                <li>Deploy a Web Application Firewall (WAF)</li>
                <li>Implement threat intelligence feed integration</li>
                <li>Set up automated security alerting</li>
                <li>Conduct regular security assessments</li>
            </ol>
        </div>
    </div>
    """
    
    html += get_html_footer()
    
    with open(output_path, 'w') as f:
        f.write(html)


def analyze_performance(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Perform comprehensive performance anomaly analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing performance analysis results.
    """
    response_times: list = []
    endpoint_times: defaultdict = defaultdict(list)
    service_times: defaultdict = defaultdict(list)
    slow_requests: list = []
    performance_warnings: list = []
    timeline_performance: defaultdict = defaultdict(list)
    
    for log in logs:
        http_info = log.get('http', {})
        response_time = http_info.get('response_time_ms')
        endpoint = http_info.get('endpoint', 'Unknown')
        service = log.get('service', 'Unknown')
        timestamp = log.get('@timestamp', '')
        message = log.get('message', '')
        perf_info = log.get('performance', {})
        
        if response_time is not None:
            response_times.append(response_time)
            endpoint_times[endpoint].append(response_time)
            service_times[service].append(response_time)
            
            hour = timestamp[:13] if timestamp else 'Unknown'
            timeline_performance[hour].append(response_time)
            
            if response_time > 1000:
                slow_requests.append({
                    'timestamp': timestamp,
                    'service': service,
                    'endpoint': endpoint,
                    'response_time_ms': response_time,
                    'status_code': http_info.get('status_code'),
                    'method': http_info.get('method')
                })
        
        if perf_info or 'slow' in message.lower() or 'memory' in message.lower():
            performance_warnings.append({
                'timestamp': timestamp,
                'service': service,
                'message': message,
                'read_latency_ms': perf_info.get('read_latency_ms'),
                'write_latency_ms': perf_info.get('write_latency_ms'),
                'iops': perf_info.get('iops')
            })
    
    def calc_percentile(data: list, percentile: float) -> float:
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    overall_stats = {}
    if response_times:
        overall_stats = {
            'min': min(response_times),
            'max': max(response_times),
            'avg': round(statistics.mean(response_times), 2),
            'median': round(statistics.median(response_times), 2),
            'p95': round(calc_percentile(response_times, 95), 2),
            'p99': round(calc_percentile(response_times, 99), 2),
            'std_dev': round(statistics.stdev(response_times), 2) if len(response_times) > 1 else 0
        }
    
    endpoint_stats = {}
    for endpoint, times in endpoint_times.items():
        if times:
            endpoint_stats[endpoint] = {
                'count': len(times),
                'avg': round(statistics.mean(times), 2),
                'p95': round(calc_percentile(times, 95), 2),
                'max': max(times),
                'slow_count': len([t for t in times if t > 1000])
            }
    
    endpoint_stats = dict(sorted(endpoint_stats.items(), 
                                  key=lambda x: x[1]['avg'], reverse=True))
    
    service_stats = {}
    for service, times in service_times.items():
        if times:
            service_stats[service] = {
                'count': len(times),
                'avg': round(statistics.mean(times), 2),
                'p95': round(calc_percentile(times, 95), 2),
                'max': max(times),
                'error_prone': len([t for t in times if t > 5000])
            }
    
    timeline_stats = {}
    for hour, times in sorted(timeline_performance.items()):
        if times:
            timeline_stats[hour] = {
                'avg': round(statistics.mean(times), 2),
                'max': max(times),
                'count': len(times)
            }
    
    slow_requests.sort(key=lambda x: x['response_time_ms'], reverse=True)
    
    bottlenecks = []
    for endpoint, stats in list(endpoint_stats.items())[:5]:
        if stats['avg'] > 1000:
            bottlenecks.append({
                'type': 'Slow Endpoint',
                'target': endpoint,
                'avg_response_time': stats['avg'],
                'recommendation': 'Optimize database queries, add caching, or scale horizontally'
            })
    
    for service, stats in service_stats.items():
        if stats['error_prone'] > 5:
            bottlenecks.append({
                'type': 'Service Degradation',
                'target': service,
                'error_prone_requests': stats['error_prone'],
                'recommendation': 'Review service health, check resource utilization'
            })
    
    return {
        'total_logs': len(logs),
        'total_requests': len(response_times),
        'overall_stats': overall_stats,
        'endpoint_stats': endpoint_stats,
        'service_stats': service_stats,
        'slow_requests': slow_requests[:20],
        'slow_request_count': len(slow_requests),
        'performance_warnings': performance_warnings,
        'timeline_stats': timeline_stats,
        'bottlenecks': bottlenecks
    }


def generate_performance_report(analysis: dict[str, Any], output_path: str) -> None:
    """
    Generate HTML performance analysis report.

    Args:
        analysis: Performance analysis results.
        output_path: Path to save the HTML report.
    """
    html = get_html_header("Performance Anomaly Analysis Report")
    
    stats = analysis['overall_stats']
    
    html += f"""
    <h1>Performance Anomaly Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    
    <div class="summary-box">
        <h2 style="color: white; border: none; margin-top: 0;">Performance Summary</h2>
        <p>Analyzed {analysis['total_requests']} requests. Average response time: 
        <strong>{stats.get('avg', 'N/A')}ms</strong>. 
        {analysis['slow_request_count']} requests exceeded 1000ms threshold.</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric-card">
            <div class="metric-value">{stats.get('avg', 'N/A')}</div>
            <div class="metric-label">Avg Response (ms)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{stats.get('p95', 'N/A')}</div>
            <div class="metric-label">P95 Response (ms)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{stats.get('p99', 'N/A')}</div>
            <div class="metric-label">P99 Response (ms)</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{analysis['slow_request_count']}</div>
            <div class="metric-label">Slow Requests (&gt;1s)</div>
        </div>
    </div>
    
    <div class="section">
        <h2>1. Overall Response Time Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value (ms)</th></tr>
            <tr><td>Minimum</td><td>{stats.get('min', 'N/A')}</td></tr>
            <tr><td>Maximum</td><td>{stats.get('max', 'N/A')}</td></tr>
            <tr><td>Average</td><td>{stats.get('avg', 'N/A')}</td></tr>
            <tr><td>Median</td><td>{stats.get('median', 'N/A')}</td></tr>
            <tr><td>95th Percentile</td><td>{stats.get('p95', 'N/A')}</td></tr>
            <tr><td>99th Percentile</td><td>{stats.get('p99', 'N/A')}</td></tr>
            <tr><td>Standard Deviation</td><td>{stats.get('std_dev', 'N/A')}</td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>2. Endpoint Performance Analysis</h2>
        <table>
            <tr><th>Endpoint</th><th>Request Count</th><th>Avg (ms)</th>
                <th>P95 (ms)</th><th>Max (ms)</th><th>Slow Requests</th></tr>
    """
    
    for endpoint, ep_stats in list(analysis['endpoint_stats'].items())[:10]:
        slow_class = "severity-high" if ep_stats['slow_count'] > 5 else ""
        html += f"""<tr>
            <td>{endpoint}</td>
            <td>{ep_stats['count']}</td>
            <td>{ep_stats['avg']}</td>
            <td>{ep_stats['p95']}</td>
            <td>{ep_stats['max']}</td>
            <td><span class="{slow_class}">{ep_stats['slow_count']}</span></td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>3. Service Performance Analysis</h2>
        <table>
            <tr><th>Service</th><th>Request Count</th><th>Avg (ms)</th>
                <th>P95 (ms)</th><th>Max (ms)</th><th>Error-Prone</th></tr>
    """
    
    for service, svc_stats in analysis['service_stats'].items():
        error_class = "severity-high" if svc_stats['error_prone'] > 3 else ""
        html += f"""<tr>
            <td>{service}</td>
            <td>{svc_stats['count']}</td>
            <td>{svc_stats['avg']}</td>
            <td>{svc_stats['p95']}</td>
            <td>{svc_stats['max']}</td>
            <td><span class="{error_class}">{svc_stats['error_prone']}</span></td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>4. Slowest Requests</h2>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Endpoint</th>
                <th>Method</th><th>Response Time (ms)</th><th>Status</th></tr>
    """
    
    for req in analysis['slow_requests'][:15]:
        time_class = "severity-critical" if req['response_time_ms'] > 10000 else "severity-high"
        html += f"""<tr>
            <td>{req['timestamp']}</td>
            <td>{req['service']}</td>
            <td>{req['endpoint']}</td>
            <td>{req['method']}</td>
            <td><span class="{time_class}">{req['response_time_ms']}</span></td>
            <td>{req['status_code']}</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>5. Performance Timeline</h2>
        <table>
            <tr><th>Time Period</th><th>Avg Response (ms)</th>
                <th>Max Response (ms)</th><th>Request Count</th></tr>
    """
    
    for hour, t_stats in analysis['timeline_stats'].items():
        html += f"""<tr>
            <td>{hour}</td>
            <td>{t_stats['avg']}</td>
            <td>{t_stats['max']}</td>
            <td>{t_stats['count']}</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>6. Performance Warnings</h2>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Message</th>
                <th>Read Latency</th><th>Write Latency</th><th>IOPS</th></tr>
    """
    
    for warning in analysis['performance_warnings'][:15]:
        html += f"""<tr>
            <td>{warning['timestamp']}</td>
            <td>{warning['service']}</td>
            <td>{warning['message'][:50]}...</td>
            <td>{warning['read_latency_ms'] or 'N/A'}</td>
            <td>{warning['write_latency_ms'] or 'N/A'}</td>
            <td>{warning['iops'] or 'N/A'}</td>
        </tr>"""
    
    html += """
        </table>
    </div>
    
    <div class="section">
        <h2>7. Identified Bottlenecks</h2>
    """
    
    for bottleneck in analysis['bottlenecks']:
        html += f"""
        <div class="warning">
            <h3>{bottleneck['type']}: {bottleneck['target']}</h3>
            <p><strong>Issue:</strong> 
            {'Average response time: ' + str(bottleneck.get('avg_response_time', 'N/A')) + 'ms' 
             if 'avg_response_time' in bottleneck else 
             'Error-prone requests: ' + str(bottleneck.get('error_prone_requests', 'N/A'))}</p>
            <p><strong>Recommendation:</strong> {bottleneck['recommendation']}</p>
        </div>
        """
    
    html += """
    </div>
    
    <div class="section">
        <h2>8. Capacity Planning Recommendations</h2>
        <div class="recommendation">
            <h3>Scaling Recommendations</h3>
            <ol>
                <li>Consider horizontal scaling for services with high P95 latency</li>
                <li>Implement caching for frequently accessed endpoints</li>
                <li>Optimize database queries for slow endpoints</li>
                <li>Add connection pooling for database-heavy services</li>
                <li>Consider async processing for long-running operations</li>
            </ol>
        </div>
        <div class="recommendation">
            <h3>Monitoring Improvements</h3>
            <ol>
                <li>Set up alerts for P95 latency exceeding thresholds</li>
                <li>Monitor database connection pool utilization</li>
                <li>Track memory and CPU usage per service</li>
                <li>Implement distributed tracing for request flow analysis</li>
            </ol>
        </div>
    </div>
    """
    
    html += get_html_footer()
    
    with open(output_path, 'w') as f:
        f.write(html)


def generate_summary_report(
    error_analysis: dict[str, Any],
    security_analysis: dict[str, Any],
    performance_analysis: dict[str, Any],
    output_path: str
) -> None:
    """
    Generate consolidated summary HTML report.

    Args:
        error_analysis: Error analysis results.
        security_analysis: Security analysis results.
        performance_analysis: Performance analysis results.
        output_path: Path to save the HTML report.
    """
    html = get_html_header("Elastic Logs Analysis Summary")
    
    critical_security = len([f for f in security_analysis['findings'] 
                            if f['severity'] == 'Critical'])
    
    html += f"""
    <h1>Elastic Logs Analysis Summary</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    <p class="timestamp">Log File: logs/elastic_logs_30_11_25.json</p>
    
    <div class="summary-box">
        <h2 style="color: white; border: none; margin-top: 0;">Executive Summary</h2>
        <p>Comprehensive analysis of {error_analysis['total_logs']} log entries revealed 
        significant findings across error patterns, security threats, and performance anomalies. 
        Immediate attention is required for {critical_security} critical security issues and 
        {error_analysis['total_errors']} system errors.</p>
    </div>
    
    <div class="metric-grid">
        <div class="metric-card">
            <div class="metric-value">{error_analysis['total_logs']}</div>
            <div class="metric-label">Total Log Entries</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #ff4757;">{error_analysis['total_errors']}</div>
            <div class="metric-label">Total Errors</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #ff4757;">{critical_security}</div>
            <div class="metric-label">Critical Security Issues</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{performance_analysis['slow_request_count']}</div>
            <div class="metric-label">Slow Requests</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Error Analysis Highlights</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{error_analysis['error_rate']}%</div>
                <div class="metric-label">Error Rate</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len(error_analysis['service_counts'])}</div>
                <div class="metric-label">Affected Services</div>
            </div>
        </div>
        <h3>Top Error Types</h3>
        <table>
            <tr><th>Error Message</th><th>Count</th></tr>
    """
    
    for msg, count in list(error_analysis['message_counts'].items())[:5]:
        html += f"<tr><td>{msg}</td><td>{count}</td></tr>"
    
    html += """
        </table>
        <p><a href="error_analysis_report.html">View Full Error Analysis Report</a></p>
    </div>
    
    <div class="section">
        <h2>Security Analysis Highlights</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{0}</div>
                <div class="metric-label">Auth Failures</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{1}</div>
                <div class="metric-label">Injection Attempts</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{2}</div>
                <div class="metric-label">High-Risk IPs</div>
            </div>
        </div>
    """.format(
        security_analysis['auth_failure_count'],
        len(security_analysis['injection_attempts']),
        len(security_analysis['high_risk_ips'])
    )
    
    if security_analysis['findings']:
        html += """
        <h3>Critical Findings</h3>
        <table>
            <tr><th>Category</th><th>Severity</th><th>Count</th></tr>
        """
        for finding in security_analysis['findings']:
            sev_class = f"severity-{finding['severity'].lower()}"
            html += f"""<tr>
                <td>{finding['category']}</td>
                <td><span class="{sev_class}">{finding['severity']}</span></td>
                <td>{finding['count']}</td>
            </tr>"""
        html += "</table>"
    
    html += """
        <p><a href="security_analysis_report.html">View Full Security Analysis Report</a></p>
    </div>
    
    <div class="section">
        <h2>Performance Analysis Highlights</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{0}</div>
                <div class="metric-label">Avg Response (ms)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{1}</div>
                <div class="metric-label">P95 Response (ms)</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{2}</div>
                <div class="metric-label">P99 Response (ms)</div>
            </div>
        </div>
    """.format(
        performance_analysis['overall_stats'].get('avg', 'N/A'),
        performance_analysis['overall_stats'].get('p95', 'N/A'),
        performance_analysis['overall_stats'].get('p99', 'N/A')
    )
    
    html += """
        <h3>Slowest Endpoints</h3>
        <table>
            <tr><th>Endpoint</th><th>Avg Response (ms)</th><th>Slow Requests</th></tr>
    """
    
    for endpoint, ep_stats in list(performance_analysis['endpoint_stats'].items())[:5]:
        html += f"""<tr>
            <td>{endpoint}</td>
            <td>{ep_stats['avg']}</td>
            <td>{ep_stats['slow_count']}</td>
        </tr>"""
    
    html += """
        </table>
        <p><a href="performance_analysis_report.html">View Full Performance Analysis Report</a></p>
    </div>
    
    <div class="section">
        <h2>Priority Action Items</h2>
        <div class="error-box">
            <h3>Critical (Immediate Action Required)</h3>
            <ol>
                <li>Block IPs with SQL injection attempts</li>
                <li>Address database connection pool exhaustion</li>
                <li>Investigate out of memory exceptions</li>
            </ol>
        </div>
        <div class="warning">
            <h3>High Priority (Within 24 Hours)</h3>
            <ol>
                <li>Implement rate limiting for suspicious IPs</li>
                <li>Review and optimize slow endpoints</li>
                <li>Add circuit breakers for failing services</li>
            </ol>
        </div>
        <div class="recommendation">
            <h3>Medium Priority (Within 1 Week)</h3>
            <ol>
                <li>Set up comprehensive monitoring and alerting</li>
                <li>Implement caching for high-traffic endpoints</li>
                <li>Review authentication mechanisms</li>
                <li>Conduct security assessment</li>
            </ol>
        </div>
    </div>
    """
    
    html += get_html_footer()
    
    with open(output_path, 'w') as f:
        f.write(html)


def main() -> None:
    """
    Main entry point for the analysis script.

    Loads logs, performs all analyses, and generates HTML reports.
    """
    log_file = "logs/elastic_logs_30_11_25.json"
    output_dir = Path("analysis")
    output_dir.mkdir(exist_ok=True)
    
    print(f"Loading logs from {log_file}...")
    logs = load_logs(log_file)
    print(f"Loaded {len(logs)} log entries")
    
    print("\n[Task 1] Analyzing error patterns...")
    error_analysis = analyze_errors(logs)
    error_report_path = output_dir / "error_analysis_report.html"
    generate_error_report(error_analysis, str(error_report_path))
    print(f"  - Found {error_analysis['total_errors']} errors")
    print(f"  - Report saved to {error_report_path}")
    
    print("\n[Task 2] Detecting security issues...")
    security_analysis = analyze_security(logs)
    security_report_path = output_dir / "security_analysis_report.html"
    generate_security_report(security_analysis, str(security_report_path))
    print(f"  - Found {len(security_analysis['findings'])} security findings")
    print(f"  - Report saved to {security_report_path}")
    
    print("\n[Task 3] Analyzing performance anomalies...")
    performance_analysis = analyze_performance(logs)
    performance_report_path = output_dir / "performance_analysis_report.html"
    generate_performance_report(performance_analysis, str(performance_report_path))
    print(f"  - Found {performance_analysis['slow_request_count']} slow requests")
    print(f"  - Report saved to {performance_report_path}")
    
    print("\n[Summary] Generating consolidated report...")
    summary_report_path = output_dir / "analysis_summary.html"
    generate_summary_report(
        error_analysis, 
        security_analysis, 
        performance_analysis,
        str(summary_report_path)
    )
    print(f"  - Summary saved to {summary_report_path}")
    
    print("\n" + "=" * 60)
    print("Analysis Complete!")
    print("=" * 60)
    print(f"\nReports generated in {output_dir}/:")
    print(f"  - error_analysis_report.html")
    print(f"  - security_analysis_report.html")
    print(f"  - performance_analysis_report.html")
    print(f"  - analysis_summary.html")


if __name__ == "__main__":
    main()
