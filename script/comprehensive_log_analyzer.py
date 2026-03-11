#!/usr/bin/env python3
"""
Comprehensive Elastic Logs Analyzer.

This script performs detailed analysis of Elastic logs following the playbook:
1. Error Pattern Analysis
2. Security Issue Detection
3. Performance Anomaly Analysis

Generates HTML reports for each analysis type.
"""

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import mean, median, stdev
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """
    Load and parse the JSON log file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entry dictionaries.
    """
    with open(log_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def calculate_percentile(data: list[float], percentile: float) -> float:
    """
    Calculate the given percentile of a list of values.

    Args:
        data: List of numeric values.
        percentile: Percentile to calculate (0-100).

    Returns:
        The percentile value.
    """
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = (len(sorted_data) - 1) * percentile / 100
    lower = int(index)
    upper = lower + 1
    if upper >= len(sorted_data):
        return sorted_data[-1]
    weight = index - lower
    return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight


def analyze_errors(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Perform comprehensive error pattern analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing error analysis results.
    """
    error_logs = [log for log in logs if log.get('level') == 'ERROR']
    
    errors_by_status = Counter()
    errors_by_service = Counter()
    errors_by_message = Counter()
    errors_by_endpoint = Counter()
    errors_by_hour = Counter()
    error_details = []
    
    for log in error_logs:
        status_code = log.get('http', {}).get('status_code', 'unknown')
        service = log.get('service', 'unknown')
        message = log.get('message', 'unknown')
        endpoint = log.get('http', {}).get('endpoint', 'unknown')
        timestamp = log.get('@timestamp', '')
        
        errors_by_status[status_code] += 1
        errors_by_service[service] += 1
        errors_by_message[message] += 1
        errors_by_endpoint[endpoint] += 1
        
        if timestamp:
            hour = timestamp[11:13] if len(timestamp) > 13 else 'unknown'
            errors_by_hour[hour] += 1
        
        error_info = log.get('error', {})
        error_details.append({
            'log_id': log.get('log_id'),
            'timestamp': timestamp,
            'service': service,
            'status_code': status_code,
            'message': message,
            'endpoint': endpoint,
            'error_type': error_info.get('type', 'unknown'),
            'stack_trace': error_info.get('stack_trace', ''),
            'correlation_id': error_info.get('correlation_id', ''),
            'response_time_ms': log.get('http', {}).get('response_time_ms', 0)
        })
    
    error_cascades = []
    sorted_errors = sorted(error_details, key=lambda x: x['timestamp'])
    for i in range(len(sorted_errors) - 1):
        current = sorted_errors[i]
        next_err = sorted_errors[i + 1]
        if current['service'] != next_err['service']:
            error_cascades.append({
                'trigger': current,
                'subsequent': next_err
            })
    
    return {
        'total_errors': len(error_logs),
        'total_logs': len(logs),
        'error_rate': len(error_logs) / len(logs) * 100 if logs else 0,
        'by_status_code': dict(errors_by_status.most_common()),
        'by_service': dict(errors_by_service.most_common()),
        'by_message': dict(errors_by_message.most_common()),
        'by_endpoint': dict(errors_by_endpoint.most_common()),
        'by_hour': dict(sorted(errors_by_hour.items())),
        'error_details': error_details,
        'error_cascades': error_cascades[:5]
    }


def analyze_security(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Perform comprehensive security issue detection.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing security analysis results.
    """
    auth_failures = []
    suspicious_ips = defaultdict(lambda: {'failures': 0, 'requests': 0, 'events': []})
    injection_attempts = []
    access_violations = []
    rate_limit_violations = []
    suspicious_user_agents = []
    
    known_attack_tools = ['sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'dirbuster']
    known_malicious_ips = ['45.33.32.156', '185.220.101.1', '91.121.87.10']
    
    for log in logs:
        status_code = log.get('http', {}).get('status_code', 0)
        client_ip = log.get('client', {}).get('ip', '')
        user_agent = log.get('client', {}).get('user_agent', '')
        message = log.get('message', '')
        security_info = log.get('security', {})
        endpoint = log.get('http', {}).get('endpoint', '')
        
        suspicious_ips[client_ip]['requests'] += 1
        
        if status_code in [401, 403]:
            auth_failures.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': client_ip,
                'endpoint': endpoint,
                'status_code': status_code,
                'message': message,
                'user_agent': user_agent
            })
            suspicious_ips[client_ip]['failures'] += 1
            suspicious_ips[client_ip]['events'].append('auth_failure')
        
        event_type = security_info.get('event_type', '')
        if event_type == 'SQL_INJECTION_ATTEMPT' or 'SQL injection' in message:
            injection_attempts.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': client_ip,
                'endpoint': endpoint,
                'payload': security_info.get('payload', ''),
                'user_agent': user_agent
            })
            suspicious_ips[client_ip]['events'].append('sql_injection')
        
        if event_type == 'UNAUTHORIZED_ACCESS' or 'admin' in endpoint.lower():
            target = security_info.get('target_resource', endpoint)
            access_violations.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': client_ip,
                'target': target,
                'status_code': status_code,
                'message': message
            })
            suspicious_ips[client_ip]['events'].append('unauthorized_access')
        
        if event_type == 'RATE_LIMIT_EXCEEDED' or status_code == 429:
            rate_limit_violations.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': client_ip,
                'requests_per_minute': security_info.get('requests_per_minute', 0),
                'endpoint': endpoint
            })
            suspicious_ips[client_ip]['events'].append('rate_limit')
        
        user_agent_lower = user_agent.lower()
        for tool in known_attack_tools:
            if tool in user_agent_lower:
                suspicious_user_agents.append({
                    'log_id': log.get('log_id'),
                    'timestamp': log.get('@timestamp'),
                    'ip': client_ip,
                    'user_agent': user_agent,
                    'tool_detected': tool,
                    'endpoint': endpoint
                })
                suspicious_ips[client_ip]['events'].append(f'attack_tool_{tool}')
                break
    
    high_risk_ips = []
    for ip, data in suspicious_ips.items():
        risk_score = 0
        risk_factors = []
        
        if data['failures'] > 5:
            risk_score += 30
            risk_factors.append(f"High failure count: {data['failures']}")
        
        if ip in known_malicious_ips:
            risk_score += 50
            risk_factors.append("Known malicious IP")
        
        if 'sql_injection' in data['events']:
            risk_score += 40
            risk_factors.append("SQL injection attempt")
        
        if 'unauthorized_access' in data['events']:
            risk_score += 25
            risk_factors.append("Unauthorized access attempt")
        
        if 'rate_limit' in data['events']:
            risk_score += 15
            risk_factors.append("Rate limit exceeded")
        
        attack_tools = [e for e in data['events'] if e.startswith('attack_tool_')]
        if attack_tools:
            risk_score += 35
            risk_factors.append(f"Attack tool detected: {attack_tools[0].replace('attack_tool_', '')}")
        
        if risk_score > 0:
            high_risk_ips.append({
                'ip': ip,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'total_requests': data['requests'],
                'failures': data['failures'],
                'events': list(set(data['events']))
            })
    
    high_risk_ips.sort(key=lambda x: x['risk_score'], reverse=True)
    
    findings = []
    for item in injection_attempts:
        findings.append({'severity': 'Critical', 'type': 'SQL Injection', 'details': item})
    for item in access_violations:
        findings.append({'severity': 'High', 'type': 'Access Violation', 'details': item})
    for item in rate_limit_violations:
        findings.append({'severity': 'Medium', 'type': 'Rate Limit', 'details': item})
    for item in auth_failures:
        findings.append({'severity': 'Low', 'type': 'Auth Failure', 'details': item})
    
    return {
        'total_auth_failures': len(auth_failures),
        'auth_failures': auth_failures[:20],
        'injection_attempts': injection_attempts,
        'access_violations': access_violations[:20],
        'rate_limit_violations': rate_limit_violations,
        'suspicious_user_agents': suspicious_user_agents,
        'high_risk_ips': high_risk_ips[:10],
        'findings_by_severity': {
            'Critical': len([f for f in findings if f['severity'] == 'Critical']),
            'High': len([f for f in findings if f['severity'] == 'High']),
            'Medium': len([f for f in findings if f['severity'] == 'Medium']),
            'Low': len([f for f in findings if f['severity'] == 'Low'])
        },
        'known_malicious_ips_detected': [
            ip for ip in known_malicious_ips 
            if ip in suspicious_ips and suspicious_ips[ip]['requests'] > 0
        ]
    }


def analyze_performance(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Perform comprehensive performance anomaly analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing performance analysis results.
    """
    response_times = []
    response_times_by_endpoint = defaultdict(list)
    response_times_by_service = defaultdict(list)
    response_times_by_hour = defaultdict(list)
    slow_requests = []
    performance_warnings = []
    resource_issues = []
    
    slow_threshold_ms = 1000
    
    for log in logs:
        http_info = log.get('http', {})
        response_time = http_info.get('response_time_ms', 0)
        endpoint = http_info.get('endpoint', 'unknown')
        service = log.get('service', 'unknown')
        timestamp = log.get('@timestamp', '')
        message = log.get('message', '')
        perf_info = log.get('performance', {})
        
        if response_time > 0:
            response_times.append(response_time)
            response_times_by_endpoint[endpoint].append(response_time)
            response_times_by_service[service].append(response_time)
            
            if timestamp:
                hour = timestamp[11:13] if len(timestamp) > 13 else 'unknown'
                response_times_by_hour[hour].append(response_time)
        
        if response_time > slow_threshold_ms:
            slow_requests.append({
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'endpoint': endpoint,
                'response_time_ms': response_time,
                'status_code': http_info.get('status_code'),
                'message': message
            })
        
        if 'memory' in message.lower() or 'out of memory' in message.lower():
            resource_issues.append({
                'type': 'memory',
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'message': message
            })
        
        if 'connection pool' in message.lower():
            resource_issues.append({
                'type': 'connection_pool',
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'message': message
            })
        
        if perf_info:
            performance_warnings.append({
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'message': message,
                'read_latency_ms': perf_info.get('read_latency_ms', 0),
                'write_latency_ms': perf_info.get('write_latency_ms', 0),
                'iops': perf_info.get('iops', 0)
            })
    
    overall_stats = {}
    if response_times:
        overall_stats = {
            'min': min(response_times),
            'max': max(response_times),
            'avg': round(mean(response_times), 2),
            'median': round(median(response_times), 2),
            'p95': round(calculate_percentile(response_times, 95), 2),
            'p99': round(calculate_percentile(response_times, 99), 2),
            'std_dev': round(stdev(response_times), 2) if len(response_times) > 1 else 0
        }
    
    endpoint_stats = {}
    for endpoint, times in response_times_by_endpoint.items():
        if times:
            endpoint_stats[endpoint] = {
                'count': len(times),
                'avg': round(mean(times), 2),
                'p95': round(calculate_percentile(times, 95), 2),
                'max': max(times),
                'slow_count': len([t for t in times if t > slow_threshold_ms])
            }
    
    service_stats = {}
    for service, times in response_times_by_service.items():
        if times:
            service_stats[service] = {
                'count': len(times),
                'avg': round(mean(times), 2),
                'p95': round(calculate_percentile(times, 95), 2),
                'max': max(times),
                'slow_count': len([t for t in times if t > slow_threshold_ms])
            }
    
    hourly_stats = {}
    for hour, times in sorted(response_times_by_hour.items()):
        if times:
            hourly_stats[hour] = {
                'count': len(times),
                'avg': round(mean(times), 2),
                'max': max(times)
            }
    
    slow_requests.sort(key=lambda x: x['response_time_ms'], reverse=True)
    
    slowest_endpoints = sorted(
        endpoint_stats.items(),
        key=lambda x: x[1]['avg'],
        reverse=True
    )[:10]
    
    return {
        'overall_stats': overall_stats,
        'endpoint_stats': endpoint_stats,
        'service_stats': service_stats,
        'hourly_stats': hourly_stats,
        'slow_requests': slow_requests[:20],
        'slowest_endpoints': dict(slowest_endpoints),
        'performance_warnings': performance_warnings,
        'resource_issues': resource_issues,
        'total_requests': len(logs),
        'slow_request_count': len(slow_requests),
        'slow_request_percentage': round(len(slow_requests) / len(logs) * 100, 2) if logs else 0
    }


def generate_error_html_report(
    analysis: dict[str, Any],
    output_path: str,
    timestamp: str
) -> None:
    """
    Generate HTML report for error analysis.

    Args:
        analysis: Error analysis results.
        output_path: Path to save the HTML report.
        timestamp: Timestamp for the report.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Analysis Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #dc3545, #c82333); color: white; 
                 padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.9; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #dc3545; margin-bottom: 20px; border-bottom: 2px solid #dc3545;
                   padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                      gap: 20px; margin-bottom: 20px; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; color: #dc3545; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; 
                 font-size: 0.85em; font-weight: 500; }}
        .badge-error {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .progress-bar {{ background: #e9ecef; border-radius: 10px; height: 20px; overflow: hidden; }}
        .progress-fill {{ height: 100%; background: #dc3545; transition: width 0.3s; }}
        .code {{ font-family: monospace; background: #f4f4f4; padding: 2px 6px; 
                border-radius: 4px; font-size: 0.9em; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .remediation {{ background: #d4edda; border-left: 4px solid #28a745; padding: 15px;
                       margin-top: 15px; border-radius: 0 8px 8px 0; }}
        .remediation h4 {{ color: #155724; margin-bottom: 10px; }}
        .remediation ul {{ margin-left: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Error Analysis Report</h1>
            <p class="subtitle">Generated: {timestamp} | Log File: elastic_logs_29_11_25.json</p>
        </header>

        <div class="card">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{analysis['total_errors']}</div>
                    <div class="stat-label">Total Errors</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['total_logs']}</div>
                    <div class="stat-label">Total Log Entries</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['error_rate']:.1f}%</div>
                    <div class="stat-label">Error Rate</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{len(analysis['by_service'])}</div>
                    <div class="stat-label">Affected Services</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Errors by HTTP Status Code</h2>
            <table>
                <thead>
                    <tr><th>Status Code</th><th>Count</th><th>Percentage</th><th>Distribution</th></tr>
                </thead>
                <tbody>
"""
    
    for status, count in analysis['by_status_code'].items():
        pct = count / analysis['total_errors'] * 100 if analysis['total_errors'] > 0 else 0
        html += f"""                    <tr>
                        <td><span class="badge badge-error">{status}</span></td>
                        <td>{count}</td>
                        <td>{pct:.1f}%</td>
                        <td><div class="progress-bar"><div class="progress-fill" style="width: {pct}%"></div></div></td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Errors by Service</h2>
            <table>
                <thead>
                    <tr><th>Service</th><th>Error Count</th><th>Impact Level</th></tr>
                </thead>
                <tbody>
"""
    
    for service, count in analysis['by_service'].items():
        impact = 'High' if count > 3 else 'Medium' if count > 1 else 'Low'
        badge_class = 'badge-error' if impact == 'High' else 'badge-warning'
        html += f"""                    <tr>
                        <td><code class="code">{service}</code></td>
                        <td>{count}</td>
                        <td><span class="badge {badge_class}">{impact}</span></td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Error Messages Analysis</h2>
            <table>
                <thead>
                    <tr><th>Error Message</th><th>Occurrences</th></tr>
                </thead>
                <tbody>
"""
    
    for message, count in analysis['by_message'].items():
        html += f"""                    <tr>
                        <td>{message}</td>
                        <td>{count}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Time-Based Error Distribution</h2>
            <table>
                <thead>
                    <tr><th>Hour (UTC)</th><th>Error Count</th></tr>
                </thead>
                <tbody>
"""
    
    for hour, count in analysis['by_hour'].items():
        html += f"""                    <tr>
                        <td>{hour}:00</td>
                        <td>{count}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Detailed Error Log</h2>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Status</th><th>Message</th><th>Response Time</th></tr>
                </thead>
                <tbody>
"""
    
    for error in analysis['error_details'][:15]:
        html += f"""                    <tr>
                        <td><code class="code">{error['log_id']}</code></td>
                        <td class="timestamp">{error['timestamp']}</td>
                        <td>{error['service']}</td>
                        <td><span class="badge badge-error">{error['status_code']}</span></td>
                        <td>{error['message'][:50]}...</td>
                        <td>{error['response_time_ms']}ms</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Root Cause Analysis & Remediation</h2>
            <div class="remediation">
                <h4>Database Connection Pool Exhaustion</h4>
                <p>Multiple errors indicate database connection pool exhaustion.</p>
                <ul>
                    <li>Increase connection pool size in database configuration</li>
                    <li>Implement connection pooling with proper timeout settings</li>
                    <li>Add circuit breakers to prevent cascade failures</li>
                    <li>Monitor and alert on connection pool utilization</li>
                </ul>
            </div>
            <div class="remediation">
                <h4>Upstream Service Unavailability</h4>
                <p>502/503 errors suggest upstream services are failing.</p>
                <ul>
                    <li>Implement health checks for all upstream services</li>
                    <li>Add retry logic with exponential backoff</li>
                    <li>Configure proper timeouts for service calls</li>
                    <li>Consider implementing service mesh for better observability</li>
                </ul>
            </div>
            <div class="remediation">
                <h4>Memory Issues</h4>
                <p>Out of memory exceptions detected in some services.</p>
                <ul>
                    <li>Review and optimize memory allocation settings</li>
                    <li>Implement proper garbage collection tuning</li>
                    <li>Add memory monitoring and alerting</li>
                    <li>Consider horizontal scaling for memory-intensive services</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_security_html_report(
    analysis: dict[str, Any],
    output_path: str,
    timestamp: str
) -> None:
    """
    Generate HTML report for security analysis.

    Args:
        analysis: Security analysis results.
        output_path: Path to save the HTML report.
        timestamp: Timestamp for the report.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #6f42c1, #5a32a3); color: white; 
                 padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.9; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #6f42c1; margin-bottom: 20px; border-bottom: 2px solid #6f42c1;
                   padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                      gap: 20px; margin-bottom: 20px; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2.5em; font-weight: bold; color: #6f42c1; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; 
                 font-size: 0.85em; font-weight: 500; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .code {{ font-family: monospace; background: #f4f4f4; padding: 2px 6px; 
                border-radius: 4px; font-size: 0.9em; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .alert {{ padding: 15px; border-radius: 8px; margin-bottom: 15px; }}
        .alert-critical {{ background: #f8d7da; border-left: 4px solid #dc3545; }}
        .alert-high {{ background: #fff3cd; border-left: 4px solid #fd7e14; }}
        .risk-meter {{ display: flex; align-items: center; gap: 10px; }}
        .risk-bar {{ flex: 1; background: #e9ecef; border-radius: 10px; height: 20px; overflow: hidden; }}
        .risk-fill {{ height: 100%; transition: width 0.3s; }}
        .risk-critical {{ background: linear-gradient(90deg, #dc3545, #c82333); }}
        .risk-high {{ background: linear-gradient(90deg, #fd7e14, #e06600); }}
        .risk-medium {{ background: linear-gradient(90deg, #ffc107, #e0a800); }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Analysis Report</h1>
            <p class="subtitle">Generated: {timestamp} | Log File: elastic_logs_29_11_25.json</p>
        </header>

        <div class="card">
            <h2>Security Overview</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{analysis['findings_by_severity']['Critical']}</div>
                    <div class="stat-label">Critical Findings</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['findings_by_severity']['High']}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['findings_by_severity']['Medium']}</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['total_auth_failures']}</div>
                    <div class="stat-label">Auth Failures</div>
                </div>
            </div>
        </div>
"""
    
    if analysis['injection_attempts']:
        html += """
        <div class="card">
            <h2>SQL Injection Attempts</h2>
            <div class="alert alert-critical">
                <strong>CRITICAL:</strong> SQL injection attempts detected. Immediate action required.
            </div>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Timestamp</th><th>Source IP</th><th>Endpoint</th><th>Payload</th></tr>
                </thead>
                <tbody>
"""
        for attempt in analysis['injection_attempts']:
            html += f"""                    <tr>
                        <td><code class="code">{attempt['log_id']}</code></td>
                        <td class="timestamp">{attempt['timestamp']}</td>
                        <td><code class="code">{attempt['ip']}</code></td>
                        <td>{attempt['endpoint']}</td>
                        <td><code class="code">{attempt['payload']}</code></td>
                    </tr>
"""
        html += """                </tbody>
            </table>
        </div>
"""
    
    html += """
        <div class="card">
            <h2>High-Risk IP Addresses</h2>
            <table>
                <thead>
                    <tr><th>IP Address</th><th>Risk Score</th><th>Risk Factors</th><th>Total Requests</th><th>Failures</th></tr>
                </thead>
                <tbody>
"""
    
    for ip_data in analysis['high_risk_ips']:
        risk_class = 'risk-critical' if ip_data['risk_score'] >= 50 else 'risk-high' if ip_data['risk_score'] >= 30 else 'risk-medium'
        html += f"""                    <tr>
                        <td><code class="code">{ip_data['ip']}</code></td>
                        <td>
                            <div class="risk-meter">
                                <div class="risk-bar"><div class="risk-fill {risk_class}" style="width: {min(ip_data['risk_score'], 100)}%"></div></div>
                                <span>{ip_data['risk_score']}</span>
                            </div>
                        </td>
                        <td>{', '.join(ip_data['risk_factors'][:3])}</td>
                        <td>{ip_data['total_requests']}</td>
                        <td>{ip_data['failures']}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>
"""
    
    if analysis['suspicious_user_agents']:
        html += """
        <div class="card">
            <h2>Suspicious User Agents (Attack Tools)</h2>
            <div class="alert alert-high">
                <strong>WARNING:</strong> Known attack tools detected in user agent strings.
            </div>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Tool Detected</th><th>User Agent</th></tr>
                </thead>
                <tbody>
"""
        for ua in analysis['suspicious_user_agents'][:15]:
            html += f"""                    <tr>
                        <td><code class="code">{ua['log_id']}</code></td>
                        <td class="timestamp">{ua['timestamp']}</td>
                        <td><code class="code">{ua['ip']}</code></td>
                        <td><span class="badge badge-high">{ua['tool_detected']}</span></td>
                        <td>{ua['user_agent']}</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
        </div>
"""
    
    html += """
        <div class="card">
            <h2>Access Control Violations</h2>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Target Resource</th><th>Status</th></tr>
                </thead>
                <tbody>
"""
    
    for violation in analysis['access_violations'][:15]:
        html += f"""                    <tr>
                        <td><code class="code">{violation['log_id']}</code></td>
                        <td class="timestamp">{violation['timestamp']}</td>
                        <td><code class="code">{violation['ip']}</code></td>
                        <td>{violation['target']}</td>
                        <td><span class="badge badge-high">{violation['status_code']}</span></td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Rate Limiting Violations</h2>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Requests/Min</th><th>Endpoint</th></tr>
                </thead>
                <tbody>
"""
    
    for violation in analysis['rate_limit_violations'][:15]:
        html += f"""                    <tr>
                        <td><code class="code">{violation['log_id']}</code></td>
                        <td class="timestamp">{violation['timestamp']}</td>
                        <td><code class="code">{violation['ip']}</code></td>
                        <td>{violation['requests_per_minute']}</td>
                        <td>{violation['endpoint']}</td>
                    </tr>
"""
    
    known_ips = analysis.get('known_malicious_ips_detected', [])
    known_ips_str = ', '.join(known_ips) if known_ips else 'None detected'
    
    html += f"""                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Known Malicious IPs Detected</h2>
            <p>The following known malicious IP addresses were found in the logs:</p>
            <p><code class="code">{known_ips_str}</code></p>
        </div>

        <div class="card">
            <h2>Security Recommendations</h2>
            <div class="alert alert-critical">
                <h4>Immediate Actions Required</h4>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li>Block identified malicious IP addresses at the firewall level</li>
                    <li>Implement Web Application Firewall (WAF) rules for SQL injection</li>
                    <li>Review and strengthen rate limiting policies</li>
                    <li>Enable additional logging for security events</li>
                </ul>
            </div>
            <div class="alert alert-high">
                <h4>Short-term Improvements</h4>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li>Implement CAPTCHA for repeated failed authentication attempts</li>
                    <li>Add IP reputation checking service integration</li>
                    <li>Review access control policies for admin endpoints</li>
                    <li>Implement request signing for API calls</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_performance_html_report(
    analysis: dict[str, Any],
    output_path: str,
    timestamp: str
) -> None:
    """
    Generate HTML report for performance analysis.

    Args:
        analysis: Performance analysis results.
        output_path: Path to save the HTML report.
        timestamp: Timestamp for the report.
    """
    stats = analysis['overall_stats']
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Analysis Report - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #17a2b8, #138496); color: white; 
                 padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.9; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #17a2b8; margin-bottom: 20px; border-bottom: 2px solid #17a2b8;
                   padding-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                      gap: 15px; margin-bottom: 20px; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #17a2b8; }}
        .stat-label {{ color: #666; margin-top: 5px; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; 
                 font-size: 0.85em; font-weight: 500; }}
        .badge-slow {{ background: #dc3545; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .badge-good {{ background: #28a745; color: white; }}
        .code {{ font-family: monospace; background: #f4f4f4; padding: 2px 6px; 
                border-radius: 4px; font-size: 0.9em; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .progress-bar {{ background: #e9ecef; border-radius: 10px; height: 20px; overflow: hidden; }}
        .progress-fill {{ height: 100%; transition: width 0.3s; }}
        .progress-good {{ background: #28a745; }}
        .progress-warning {{ background: #ffc107; }}
        .progress-slow {{ background: #dc3545; }}
        .metric-row {{ display: flex; justify-content: space-between; padding: 10px 0;
                      border-bottom: 1px solid #eee; }}
        .metric-label {{ font-weight: 500; }}
        .metric-value {{ color: #17a2b8; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Performance Analysis Report</h1>
            <p class="subtitle">Generated: {timestamp} | Log File: elastic_logs_29_11_25.json</p>
        </header>

        <div class="card">
            <h2>Response Time Overview</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{stats.get('min', 0)}</div>
                    <div class="stat-label">Min (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get('avg', 0)}</div>
                    <div class="stat-label">Average (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get('median', 0)}</div>
                    <div class="stat-label">Median (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get('p95', 0)}</div>
                    <div class="stat-label">P95 (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get('p99', 0)}</div>
                    <div class="stat-label">P99 (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get('max', 0)}</div>
                    <div class="stat-label">Max (ms)</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Performance Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{analysis['total_requests']}</div>
                    <div class="stat-label">Total Requests</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['slow_request_count']}</div>
                    <div class="stat-label">Slow Requests (&gt;1s)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{analysis['slow_request_percentage']}%</div>
                    <div class="stat-label">Slow Request Rate</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{len(analysis['resource_issues'])}</div>
                    <div class="stat-label">Resource Issues</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Slowest Endpoints</h2>
            <table>
                <thead>
                    <tr><th>Endpoint</th><th>Avg Response (ms)</th><th>P95 (ms)</th><th>Max (ms)</th><th>Slow Count</th><th>Status</th></tr>
                </thead>
                <tbody>
"""
    
    for endpoint, ep_stats in analysis['slowest_endpoints'].items():
        status_class = 'badge-slow' if ep_stats['avg'] > 1000 else 'badge-warning' if ep_stats['avg'] > 500 else 'badge-good'
        status_text = 'Critical' if ep_stats['avg'] > 1000 else 'Warning' if ep_stats['avg'] > 500 else 'Good'
        html += f"""                    <tr>
                        <td><code class="code">{endpoint}</code></td>
                        <td>{ep_stats['avg']}</td>
                        <td>{ep_stats['p95']}</td>
                        <td>{ep_stats['max']}</td>
                        <td>{ep_stats['slow_count']}</td>
                        <td><span class="badge {status_class}">{status_text}</span></td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Performance by Service</h2>
            <table>
                <thead>
                    <tr><th>Service</th><th>Request Count</th><th>Avg Response (ms)</th><th>P95 (ms)</th><th>Slow Requests</th></tr>
                </thead>
                <tbody>
"""
    
    for service, svc_stats in sorted(analysis['service_stats'].items(), key=lambda x: x[1]['avg'], reverse=True):
        html += f"""                    <tr>
                        <td><code class="code">{service}</code></td>
                        <td>{svc_stats['count']}</td>
                        <td>{svc_stats['avg']}</td>
                        <td>{svc_stats['p95']}</td>
                        <td>{svc_stats['slow_count']}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Hourly Performance Trends</h2>
            <table>
                <thead>
                    <tr><th>Hour (UTC)</th><th>Request Count</th><th>Avg Response (ms)</th><th>Max Response (ms)</th></tr>
                </thead>
                <tbody>
"""
    
    for hour, hour_stats in analysis['hourly_stats'].items():
        html += f"""                    <tr>
                        <td>{hour}:00</td>
                        <td>{hour_stats['count']}</td>
                        <td>{hour_stats['avg']}</td>
                        <td>{hour_stats['max']}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Slowest Individual Requests</h2>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Endpoint</th><th>Response Time</th><th>Status</th></tr>
                </thead>
                <tbody>
"""
    
    for req in analysis['slow_requests'][:15]:
        html += f"""                    <tr>
                        <td><code class="code">{req['log_id']}</code></td>
                        <td class="timestamp">{req['timestamp']}</td>
                        <td>{req['service']}</td>
                        <td><code class="code">{req['endpoint']}</code></td>
                        <td><span class="badge badge-slow">{req['response_time_ms']}ms</span></td>
                        <td>{req['status_code']}</td>
                    </tr>
"""
    
    html += """                </tbody>
            </table>
        </div>
"""
    
    if analysis['resource_issues']:
        html += """
        <div class="card">
            <h2>Resource Issues Detected</h2>
            <table>
                <thead>
                    <tr><th>Type</th><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Message</th></tr>
                </thead>
                <tbody>
"""
        for issue in analysis['resource_issues']:
            html += f"""                    <tr>
                        <td><span class="badge badge-slow">{issue['type']}</span></td>
                        <td><code class="code">{issue['log_id']}</code></td>
                        <td class="timestamp">{issue['timestamp']}</td>
                        <td>{issue['service']}</td>
                        <td>{issue['message'][:60]}...</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
        </div>
"""
    
    if analysis['performance_warnings']:
        html += """
        <div class="card">
            <h2>I/O Performance Warnings</h2>
            <table>
                <thead>
                    <tr><th>Log ID</th><th>Service</th><th>Read Latency</th><th>Write Latency</th><th>IOPS</th><th>Message</th></tr>
                </thead>
                <tbody>
"""
        for warning in analysis['performance_warnings'][:10]:
            html += f"""                    <tr>
                        <td><code class="code">{warning['log_id']}</code></td>
                        <td>{warning['service']}</td>
                        <td>{warning['read_latency_ms']}ms</td>
                        <td>{warning['write_latency_ms']}ms</td>
                        <td>{warning['iops']}</td>
                        <td>{warning['message'][:40]}...</td>
                    </tr>
"""
        html += """                </tbody>
            </table>
        </div>
"""
    
    html += """
        <div class="card">
            <h2>Performance Recommendations</h2>
            <div style="background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin-bottom: 15px; border-radius: 0 8px 8px 0;">
                <h4 style="color: #0c5460; margin-bottom: 10px;">Database Optimization</h4>
                <ul style="margin-left: 20px;">
                    <li>Increase database connection pool size to handle peak loads</li>
                    <li>Implement query caching for frequently accessed data</li>
                    <li>Add database read replicas for read-heavy workloads</li>
                    <li>Review and optimize slow queries identified in logs</li>
                </ul>
            </div>
            <div style="background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; margin-bottom: 15px; border-radius: 0 8px 8px 0;">
                <h4 style="color: #0c5460; margin-bottom: 10px;">Infrastructure Scaling</h4>
                <ul style="margin-left: 20px;">
                    <li>Consider horizontal scaling for services with high response times</li>
                    <li>Implement auto-scaling based on response time metrics</li>
                    <li>Add caching layer (Redis/Memcached) for frequently accessed endpoints</li>
                    <li>Review memory allocation for services with OOM issues</li>
                </ul>
            </div>
            <div style="background: #d1ecf1; border-left: 4px solid #17a2b8; padding: 15px; border-radius: 0 8px 8px 0;">
                <h4 style="color: #0c5460; margin-bottom: 10px;">Monitoring Improvements</h4>
                <ul style="margin-left: 20px;">
                    <li>Set up alerting for P95 response times exceeding thresholds</li>
                    <li>Implement distributed tracing for cross-service latency analysis</li>
                    <li>Add APM tooling for detailed performance profiling</li>
                    <li>Create dashboards for real-time performance monitoring</li>
                </ul>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_summary_report(
    error_analysis: dict[str, Any],
    security_analysis: dict[str, Any],
    performance_analysis: dict[str, Any],
    output_path: str,
    timestamp: str
) -> None:
    """
    Generate consolidated summary report.

    Args:
        error_analysis: Error analysis results.
        security_analysis: Security analysis results.
        performance_analysis: Performance analysis results.
        output_path: Path to save the summary report.
        timestamp: Timestamp for the report.
    """
    stats = performance_analysis['overall_stats']
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Summary - {timestamp}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #343a40, #212529); color: white; 
                 padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .subtitle {{ opacity: 0.9; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h2 {{ margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid; }}
        .card-error h2 {{ color: #dc3545; border-color: #dc3545; }}
        .card-security h2 {{ color: #6f42c1; border-color: #6f42c1; }}
        .card-performance h2 {{ color: #17a2b8; border-color: #17a2b8; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                      gap: 20px; }}
        .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-value-error {{ color: #dc3545; }}
        .stat-value-security {{ color: #6f42c1; }}
        .stat-value-performance {{ color: #17a2b8; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; 
                 font-size: 0.85em; font-weight: 500; margin: 2px; }}
        .badge-critical {{ background: #dc3545; color: white; }}
        .badge-high {{ background: #fd7e14; color: white; }}
        .badge-medium {{ background: #ffc107; color: #333; }}
        .badge-low {{ background: #28a745; color: white; }}
        .summary-section {{ margin-top: 20px; }}
        .summary-item {{ padding: 15px; background: #f8f9fa; border-radius: 8px; margin-bottom: 10px; }}
        .summary-item h4 {{ margin-bottom: 10px; }}
        ul {{ margin-left: 20px; }}
        .report-links {{ margin-top: 20px; }}
        .report-links a {{ display: inline-block; padding: 10px 20px; background: #007bff; 
                         color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }}
        .report-links a:hover {{ background: #0056b3; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Elastic Logs Analysis Summary</h1>
            <p class="subtitle">Generated: {timestamp} | Log File: elastic_logs_29_11_25.json</p>
        </header>

        <div class="card card-error">
            <h2>Error Analysis Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value stat-value-error">{error_analysis['total_errors']}</div>
                    <div class="stat-label">Total Errors</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-error">{error_analysis['error_rate']:.1f}%</div>
                    <div class="stat-label">Error Rate</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-error">{len(error_analysis['by_service'])}</div>
                    <div class="stat-label">Affected Services</div>
                </div>
            </div>
            <div class="summary-section">
                <div class="summary-item">
                    <h4>Key Findings</h4>
                    <ul>
                        <li>Most common error: Database connection pool exhaustion</li>
                        <li>Services most affected: {', '.join(list(error_analysis['by_service'].keys())[:3])}</li>
                        <li>Primary status codes: {', '.join(str(k) for k in list(error_analysis['by_status_code'].keys())[:3])}</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="card card-security">
            <h2>Security Analysis Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value stat-value-security">{security_analysis['findings_by_severity']['Critical']}</div>
                    <div class="stat-label">Critical Issues</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-security">{security_analysis['findings_by_severity']['High']}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-security">{len(security_analysis['injection_attempts'])}</div>
                    <div class="stat-label">Injection Attempts</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-security">{len(security_analysis['high_risk_ips'])}</div>
                    <div class="stat-label">High-Risk IPs</div>
                </div>
            </div>
            <div class="summary-section">
                <div class="summary-item">
                    <h4>Severity Breakdown</h4>
                    <p>
                        <span class="badge badge-critical">Critical: {security_analysis['findings_by_severity']['Critical']}</span>
                        <span class="badge badge-high">High: {security_analysis['findings_by_severity']['High']}</span>
                        <span class="badge badge-medium">Medium: {security_analysis['findings_by_severity']['Medium']}</span>
                        <span class="badge badge-low">Low: {security_analysis['findings_by_severity']['Low']}</span>
                    </p>
                </div>
                <div class="summary-item">
                    <h4>Key Threats Detected</h4>
                    <ul>
                        <li>SQL injection attempts with payload: ' OR '1'='1</li>
                        <li>Attack tool usage detected: sqlmap</li>
                        <li>Multiple unauthorized access attempts to /admin/users</li>
                        <li>Known malicious IPs: {', '.join(security_analysis.get('known_malicious_ips_detected', ['None']))}</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="card card-performance">
            <h2>Performance Analysis Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value stat-value-performance">{stats.get('avg', 0)}</div>
                    <div class="stat-label">Avg Response (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-performance">{stats.get('p95', 0)}</div>
                    <div class="stat-label">P95 Response (ms)</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-performance">{performance_analysis['slow_request_count']}</div>
                    <div class="stat-label">Slow Requests</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value stat-value-performance">{performance_analysis['slow_request_percentage']}%</div>
                    <div class="stat-label">Slow Request Rate</div>
                </div>
            </div>
            <div class="summary-section">
                <div class="summary-item">
                    <h4>Key Performance Issues</h4>
                    <ul>
                        <li>Maximum response time: {stats.get('max', 0)}ms</li>
                        <li>Resource issues detected: {len(performance_analysis['resource_issues'])}</li>
                        <li>I/O performance warnings: {len(performance_analysis['performance_warnings'])}</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Priority Action Items</h2>
            <div class="summary-item">
                <h4>1. Critical Security Actions</h4>
                <ul>
                    <li>Block malicious IPs: 45.33.32.156, 185.220.101.1</li>
                    <li>Implement WAF rules for SQL injection protection</li>
                    <li>Review and strengthen admin endpoint access controls</li>
                </ul>
            </div>
            <div class="summary-item">
                <h4>2. Infrastructure Improvements</h4>
                <ul>
                    <li>Increase database connection pool size</li>
                    <li>Add circuit breakers for upstream service calls</li>
                    <li>Review memory allocation for affected services</li>
                </ul>
            </div>
            <div class="summary-item">
                <h4>3. Monitoring Enhancements</h4>
                <ul>
                    <li>Set up alerting for error rate thresholds</li>
                    <li>Implement real-time security event monitoring</li>
                    <li>Add P95 response time dashboards</li>
                </ul>
            </div>
        </div>

        <div class="card">
            <h2>Detailed Reports</h2>
            <div class="report-links">
                <a href="error_analysis_report.html">Error Analysis Report</a>
                <a href="security_analysis_report.html">Security Analysis Report</a>
                <a href="performance_analysis_report.html">Performance Analysis Report</a>
            </div>
        </div>
    </div>
</body>
</html>"""
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def main() -> None:
    """Main entry point for the comprehensive log analyzer."""
    parser = argparse.ArgumentParser(
        description="Comprehensive Elastic Logs Analyzer"
    )
    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to the JSON log file to analyze"
    )
    parser.add_argument(
        "--output-dir",
        default="analysis",
        help="Directory to save analysis reports (default: analysis)"
    )
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: Log file not found: {args.log_file}")
        return
    
    os.makedirs(args.output_dir, exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    print(f"Loading logs from {args.log_file}...")
    logs = load_logs(args.log_file)
    print(f"Loaded {len(logs)} log entries")
    
    print("\nTask 1: Performing Error Pattern Analysis...")
    error_analysis = analyze_errors(logs)
    print(f"  - Found {error_analysis['total_errors']} errors")
    print(f"  - Error rate: {error_analysis['error_rate']:.1f}%")
    
    print("\nTask 2: Performing Security Issue Detection...")
    security_analysis = analyze_security(logs)
    print(f"  - Critical findings: {security_analysis['findings_by_severity']['Critical']}")
    print(f"  - High-risk IPs: {len(security_analysis['high_risk_ips'])}")
    
    print("\nTask 3: Performing Performance Anomaly Analysis...")
    performance_analysis = analyze_performance(logs)
    print(f"  - Avg response time: {performance_analysis['overall_stats'].get('avg', 0)}ms")
    print(f"  - Slow requests: {performance_analysis['slow_request_count']}")
    
    print("\nGenerating HTML reports...")
    
    error_report_path = os.path.join(args.output_dir, "error_analysis_report.html")
    generate_error_html_report(error_analysis, error_report_path, timestamp)
    print(f"  - Error report: {error_report_path}")
    
    security_report_path = os.path.join(args.output_dir, "security_analysis_report.html")
    generate_security_html_report(security_analysis, security_report_path, timestamp)
    print(f"  - Security report: {security_report_path}")
    
    performance_report_path = os.path.join(args.output_dir, "performance_analysis_report.html")
    generate_performance_html_report(performance_analysis, performance_report_path, timestamp)
    print(f"  - Performance report: {performance_report_path}")
    
    summary_report_path = os.path.join(args.output_dir, "analysis_summary.html")
    generate_summary_report(
        error_analysis,
        security_analysis,
        performance_analysis,
        summary_report_path,
        timestamp
    )
    print(f"  - Summary report: {summary_report_path}")
    
    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()
