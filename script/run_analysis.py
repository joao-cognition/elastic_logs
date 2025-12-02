#!/usr/bin/env python3
"""
Comprehensive Elastic Logs Analysis Script.

This script performs three types of analysis on Elastic logs:
1. Error Pattern Analysis
2. Security Issue Detection
3. Performance Anomaly Analysis

Following the playbook specifications for detailed log analysis.
"""

import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean, median, stdev
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load and parse the JSON log file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entries as dictionaries.
    """
    with open(log_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def calculate_percentile(data: list[float], percentile: float) -> float:
    """Calculate the percentile value from a list of numbers.

    Args:
        data: List of numeric values.
        percentile: Percentile to calculate (0-100).

    Returns:
        The percentile value.
    """
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = (percentile / 100) * (len(sorted_data) - 1)
    lower = int(index)
    upper = lower + 1
    if upper >= len(sorted_data):
        return sorted_data[-1]
    weight = index - lower
    return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight


def analyze_errors(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive error pattern analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing error analysis results.
    """
    error_logs = [log for log in logs if log.get('level') == 'ERROR']

    errors_by_status_code: Counter[int] = Counter()
    errors_by_service: Counter[str] = Counter()
    errors_by_message: Counter[str] = Counter()
    errors_by_endpoint: Counter[str] = Counter()
    errors_by_hour: Counter[str] = Counter()
    error_details: list[dict[str, Any]] = []

    for log in error_logs:
        status_code = log.get('http', {}).get('status_code', 0)
        service = log.get('service', 'unknown')
        message = log.get('message', 'unknown')
        endpoint = log.get('http', {}).get('endpoint', 'unknown')
        timestamp = log.get('@timestamp', '')

        errors_by_status_code[status_code] += 1
        errors_by_service[service] += 1
        errors_by_message[message] += 1
        errors_by_endpoint[endpoint] += 1

        if timestamp:
            hour = timestamp[11:13] if len(timestamp) > 13 else 'unknown'
            errors_by_hour[hour] += 1

        error_details.append({
            'log_id': log.get('log_id'),
            'timestamp': timestamp,
            'service': service,
            'status_code': status_code,
            'message': message,
            'endpoint': endpoint,
            'correlation_id': log.get('error', {}).get('correlation_id'),
            'stack_trace': log.get('error', {}).get('stack_trace'),
            'response_time_ms': log.get('http', {}).get('response_time_ms', 0)
        })

    error_cascades = detect_error_cascades(error_logs)
    root_causes = identify_root_causes(errors_by_message)

    return {
        'total_errors': len(error_logs),
        'total_logs': len(logs),
        'error_rate': round(len(error_logs) / len(logs) * 100, 2) if logs else 0,
        'by_status_code': dict(errors_by_status_code.most_common()),
        'by_service': dict(errors_by_service.most_common()),
        'by_message': dict(errors_by_message.most_common()),
        'by_endpoint': dict(errors_by_endpoint.most_common()),
        'by_hour': dict(sorted(errors_by_hour.items())),
        'error_details': error_details,
        'error_cascades': error_cascades,
        'root_causes': root_causes
    }


def detect_error_cascades(error_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect potential error cascades (errors occurring in quick succession).

    Args:
        error_logs: List of error log entries.

    Returns:
        List of detected error cascade patterns.
    """
    cascades: list[dict[str, Any]] = []
    sorted_errors = sorted(error_logs, key=lambda x: x.get('@timestamp', ''))

    for i in range(len(sorted_errors) - 1):
        current = sorted_errors[i]
        next_error = sorted_errors[i + 1]

        current_time = current.get('@timestamp', '')
        next_time = next_error.get('@timestamp', '')

        if current_time and next_time:
            current_service = current.get('service', '')
            next_service = next_error.get('service', '')

            if current_service != next_service:
                cascades.append({
                    'trigger_service': current_service,
                    'affected_service': next_service,
                    'trigger_time': current_time,
                    'affected_time': next_time,
                    'trigger_message': current.get('message', ''),
                    'affected_message': next_error.get('message', '')
                })

    return cascades[:10]


def identify_root_causes(errors_by_message: Counter[str]) -> list[dict[str, str]]:
    """Identify root causes and suggest remediation for common errors.

    Args:
        errors_by_message: Counter of error messages.

    Returns:
        List of root cause analysis with remediation suggestions.
    """
    root_causes = []

    remediation_map = {
        'database connection pool exhausted': {
            'root_cause': 'Database connection pool is undersized for current load',
            'remediation': 'Increase connection pool size, optimize query performance, '
                          'implement connection pooling best practices'
        },
        'out of memory exception': {
            'root_cause': 'Application memory limits exceeded, possible memory leak',
            'remediation': 'Increase heap size, analyze memory usage patterns, '
                          'implement proper garbage collection tuning'
        },
        'circuit breaker open': {
            'root_cause': 'Downstream service failures triggered circuit breaker',
            'remediation': 'Investigate downstream service health, implement retry logic, '
                          'consider fallback mechanisms'
        },
        'upstream service unavailable': {
            'root_cause': 'Upstream dependency is down or unreachable',
            'remediation': 'Check upstream service health, implement service mesh, '
                          'add health checks and monitoring'
        },
        'request exceeded 30s limit': {
            'root_cause': 'Long-running requests causing timeouts',
            'remediation': 'Optimize slow queries, implement async processing, '
                          'consider increasing timeout for specific endpoints'
        },
        'null pointer exception': {
            'root_cause': 'Null reference in application code',
            'remediation': 'Add null checks, use Optional types, '
                          'implement defensive programming practices'
        }
    }

    for message, count in errors_by_message.most_common():
        message_lower = message.lower()
        for pattern, analysis in remediation_map.items():
            if pattern in message_lower:
                root_causes.append({
                    'error_message': message,
                    'count': count,
                    'root_cause': analysis['root_cause'],
                    'remediation': analysis['remediation']
                })
                break

    return root_causes


def analyze_security(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive security issue detection.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing security analysis results.
    """
    security_events: list[dict[str, Any]] = []
    auth_failures: list[dict[str, Any]] = []
    injection_attempts: list[dict[str, Any]] = []
    unauthorized_access: list[dict[str, Any]] = []
    rate_limit_violations: list[dict[str, Any]] = []
    xss_attempts: list[dict[str, Any]] = []

    ip_failure_count: Counter[str] = Counter()
    ip_events: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    suspicious_user_agents: list[dict[str, Any]] = []

    attack_tools = ['sqlmap', 'nikto', 'nmap', 'burp', 'dirbuster', 'gobuster', 'hydra']

    for log in logs:
        security_info = log.get('security', {})
        client_info = log.get('client', {})
        http_info = log.get('http', {})

        ip = client_info.get('ip', 'unknown')
        user_agent = client_info.get('user_agent', '')
        status_code = http_info.get('status_code', 0)
        event_type = security_info.get('event_type', '')

        if status_code in [401, 403]:
            ip_failure_count[ip] += 1

        for tool in attack_tools:
            if tool in user_agent.lower():
                suspicious_user_agents.append({
                    'ip': ip,
                    'user_agent': user_agent,
                    'tool_detected': tool,
                    'timestamp': log.get('@timestamp'),
                    'endpoint': http_info.get('endpoint')
                })
                break

        if event_type:
            event_data = {
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'event_type': event_type,
                'ip': ip,
                'user_agent': user_agent,
                'endpoint': http_info.get('endpoint'),
                'status_code': status_code,
                'payload': security_info.get('payload'),
                'target_resource': security_info.get('target_resource'),
                'attempts': security_info.get('attempts'),
                'requests_per_minute': security_info.get('requests_per_minute')
            }

            security_events.append(event_data)
            ip_events[ip].append(event_data)

            if event_type == 'AUTH_FAILURE':
                auth_failures.append(event_data)
            elif event_type == 'SQL_INJECTION_ATTEMPT':
                injection_attempts.append(event_data)
            elif event_type == 'UNAUTHORIZED_ACCESS':
                unauthorized_access.append(event_data)
            elif event_type == 'RATE_LIMIT_EXCEEDED':
                rate_limit_violations.append(event_data)
            elif event_type == 'XSS_ATTEMPT':
                xss_attempts.append(event_data)

    suspicious_ips = [
        {'ip': ip, 'failure_count': count, 'events': ip_events.get(ip, [])}
        for ip, count in ip_failure_count.most_common(10)
        if count >= 2
    ]

    brute_force_candidates = [
        ip_data for ip_data in suspicious_ips
        if any(e.get('event_type') == 'AUTH_FAILURE' and (e.get('attempts') or 0) >= 5
               for e in ip_data['events'])
    ]

    severity_classification = classify_security_severity(
        injection_attempts, xss_attempts, auth_failures,
        unauthorized_access, rate_limit_violations, brute_force_candidates
    )

    return {
        'total_security_events': len(security_events),
        'auth_failures': {
            'count': len(auth_failures),
            'details': auth_failures
        },
        'injection_attempts': {
            'sql_injection_count': len(injection_attempts),
            'details': injection_attempts
        },
        'xss_attempts': {
            'count': len(xss_attempts),
            'details': xss_attempts
        },
        'unauthorized_access': {
            'count': len(unauthorized_access),
            'details': unauthorized_access
        },
        'rate_limit_violations': {
            'count': len(rate_limit_violations),
            'details': rate_limit_violations
        },
        'suspicious_ips': suspicious_ips,
        'brute_force_candidates': brute_force_candidates,
        'suspicious_user_agents': suspicious_user_agents,
        'severity_classification': severity_classification
    }


def classify_security_severity(
    injection_attempts: list[dict[str, Any]],
    xss_attempts: list[dict[str, Any]],
    auth_failures: list[dict[str, Any]],
    unauthorized_access: list[dict[str, Any]],
    rate_limit_violations: list[dict[str, Any]],
    brute_force_candidates: list[dict[str, Any]]
) -> dict[str, list[dict[str, Any]]]:
    """Classify security findings by severity level.

    Args:
        injection_attempts: List of SQL injection attempts.
        xss_attempts: List of XSS attempts.
        auth_failures: List of authentication failures.
        unauthorized_access: List of unauthorized access attempts.
        rate_limit_violations: List of rate limit violations.
        brute_force_candidates: List of potential brute force attackers.

    Returns:
        Dictionary with findings categorized by severity.
    """
    critical: list[dict[str, Any]] = []
    high: list[dict[str, Any]] = []
    medium: list[dict[str, Any]] = []
    low: list[dict[str, Any]] = []

    for attempt in injection_attempts:
        critical.append({
            'type': 'SQL Injection Attempt',
            'severity': 'CRITICAL',
            'details': attempt,
            'recommendation': 'Block IP, review WAF rules, audit input validation'
        })

    for attempt in xss_attempts:
        high.append({
            'type': 'XSS Attempt',
            'severity': 'HIGH',
            'details': attempt,
            'recommendation': 'Implement Content Security Policy, sanitize outputs'
        })

    for candidate in brute_force_candidates:
        high.append({
            'type': 'Brute Force Attack',
            'severity': 'HIGH',
            'details': candidate,
            'recommendation': 'Implement account lockout, add CAPTCHA, block IP'
        })

    for access in unauthorized_access:
        medium.append({
            'type': 'Unauthorized Access Attempt',
            'severity': 'MEDIUM',
            'details': access,
            'recommendation': 'Review access controls, audit permissions'
        })

    for violation in rate_limit_violations:
        low.append({
            'type': 'Rate Limit Violation',
            'severity': 'LOW',
            'details': violation,
            'recommendation': 'Monitor for patterns, adjust rate limits if needed'
        })

    return {
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low
    }


def analyze_performance(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive performance anomaly analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing performance analysis results.
    """
    response_times: list[float] = []
    endpoint_response_times: defaultdict[str, list[float]] = defaultdict(list)
    service_response_times: defaultdict[str, list[float]] = defaultdict(list)
    slow_requests: list[dict[str, Any]] = []
    connection_pool_warnings: list[dict[str, Any]] = []
    memory_warnings: list[dict[str, Any]] = []
    disk_io_warnings: list[dict[str, Any]] = []
    hourly_response_times: defaultdict[str, list[float]] = defaultdict(list)

    slow_threshold_ms = 1000

    for log in logs:
        http_info = log.get('http', {})
        performance_info = log.get('performance', {})
        response_time = http_info.get('response_time_ms', 0)
        endpoint = http_info.get('endpoint', 'unknown')
        service = log.get('service', 'unknown')
        timestamp = log.get('@timestamp', '')
        message = log.get('message', '')

        if response_time > 0:
            response_times.append(response_time)
            endpoint_response_times[endpoint].append(response_time)
            service_response_times[service].append(response_time)

            if timestamp and len(timestamp) > 13:
                hour = timestamp[11:13]
                hourly_response_times[hour].append(response_time)

            if response_time > slow_threshold_ms:
                slow_requests.append({
                    'log_id': log.get('log_id'),
                    'timestamp': timestamp,
                    'service': service,
                    'endpoint': endpoint,
                    'response_time_ms': response_time,
                    'status_code': http_info.get('status_code')
                })

        if 'connection pool' in message.lower():
            connection_pool_warnings.append({
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'active_connections': performance_info.get('active_connections'),
                'max_connections': performance_info.get('max_connections'),
                'wait_time_ms': performance_info.get('wait_time_ms')
            })

        if 'memory' in message.lower():
            memory_warnings.append({
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'memory_used_mb': performance_info.get('memory_used_mb'),
                'memory_limit_mb': performance_info.get('memory_limit_mb'),
                'gc_pause_ms': performance_info.get('gc_pause_ms')
            })

        if 'disk' in message.lower() or 'i/o' in message.lower():
            disk_io_warnings.append({
                'log_id': log.get('log_id'),
                'timestamp': timestamp,
                'service': service,
                'read_latency_ms': performance_info.get('read_latency_ms'),
                'write_latency_ms': performance_info.get('write_latency_ms'),
                'iops': performance_info.get('iops')
            })

    overall_stats = calculate_response_time_stats(response_times)

    endpoint_stats = {}
    for endpoint, times in endpoint_response_times.items():
        endpoint_stats[endpoint] = calculate_response_time_stats(times)

    service_stats = {}
    for service, times in service_response_times.items():
        service_stats[service] = calculate_response_time_stats(times)

    hourly_stats = {}
    for hour, times in sorted(hourly_response_times.items()):
        hourly_stats[hour] = calculate_response_time_stats(times)

    slowest_endpoints = sorted(
        endpoint_stats.items(),
        key=lambda x: x[1].get('avg', 0),
        reverse=True
    )[:10]

    capacity_insights = generate_capacity_insights(
        connection_pool_warnings, memory_warnings, hourly_stats
    )

    return {
        'overall_stats': overall_stats,
        'endpoint_stats': endpoint_stats,
        'service_stats': service_stats,
        'hourly_stats': hourly_stats,
        'slow_requests': {
            'count': len(slow_requests),
            'threshold_ms': slow_threshold_ms,
            'details': sorted(slow_requests,
                            key=lambda x: x['response_time_ms'],
                            reverse=True)[:20]
        },
        'resource_utilization': {
            'connection_pool_warnings': connection_pool_warnings,
            'memory_warnings': memory_warnings,
            'disk_io_warnings': disk_io_warnings
        },
        'slowest_endpoints': dict(slowest_endpoints),
        'capacity_insights': capacity_insights
    }


def calculate_response_time_stats(times: list[float]) -> dict[str, float]:
    """Calculate response time statistics.

    Args:
        times: List of response times in milliseconds.

    Returns:
        Dictionary with statistical measures.
    """
    if not times:
        return {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'median': 0, 'p95': 0, 'p99': 0}

    return {
        'count': len(times),
        'min': round(min(times), 2),
        'max': round(max(times), 2),
        'avg': round(mean(times), 2),
        'median': round(median(times), 2),
        'stdev': round(stdev(times), 2) if len(times) > 1 else 0,
        'p95': round(calculate_percentile(times, 95), 2),
        'p99': round(calculate_percentile(times, 99), 2)
    }


def generate_capacity_insights(
    connection_pool_warnings: list[dict[str, Any]],
    memory_warnings: list[dict[str, Any]],
    hourly_stats: dict[str, dict[str, float]]
) -> dict[str, Any]:
    """Generate capacity planning insights.

    Args:
        connection_pool_warnings: List of connection pool warnings.
        memory_warnings: List of memory warnings.
        hourly_stats: Hourly response time statistics.

    Returns:
        Dictionary with capacity planning recommendations.
    """
    insights: dict[str, Any] = {
        'peak_hours': [],
        'recommendations': []
    }

    if hourly_stats:
        peak_hours = sorted(
            hourly_stats.items(),
            key=lambda x: x[1].get('avg', 0),
            reverse=True
        )[:3]
        insights['peak_hours'] = [
            {'hour': hour, 'avg_response_time': stats.get('avg', 0)}
            for hour, stats in peak_hours
        ]

    if connection_pool_warnings:
        avg_utilization = mean([
            (w.get('active_connections', 0) / w.get('max_connections', 100)) * 100
            for w in connection_pool_warnings
            if w.get('max_connections')
        ])
        if avg_utilization > 90:
            insights['recommendations'].append({
                'area': 'Connection Pool',
                'severity': 'HIGH',
                'recommendation': f'Connection pool utilization at {avg_utilization:.1f}%. '
                                 'Consider increasing pool size or optimizing queries.'
            })

    if memory_warnings:
        avg_memory_usage = mean([
            (w.get('memory_used_mb', 0) / w.get('memory_limit_mb', 4096)) * 100
            for w in memory_warnings
            if w.get('memory_limit_mb')
        ])
        if avg_memory_usage > 85:
            insights['recommendations'].append({
                'area': 'Memory',
                'severity': 'HIGH',
                'recommendation': f'Memory usage at {avg_memory_usage:.1f}%. '
                                 'Consider increasing heap size or investigating memory leaks.'
            })

    return insights


def generate_error_html_report(analysis: dict[str, Any], output_path: str) -> None:
    """Generate HTML report for error analysis.

    Args:
        analysis: Error analysis results.
        output_path: Path to save the HTML report.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #d32f2f; border-bottom: 3px solid #d32f2f; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                         gap: 20px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 8px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card.error {{ border-left: 4px solid #d32f2f; }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .card .value {{ font-size: 32px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f8f8; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .status-500 {{ color: #d32f2f; font-weight: bold; }}
        .status-502 {{ color: #f57c00; font-weight: bold; }}
        .status-503 {{ color: #7b1fa2; font-weight: bold; }}
        .status-504 {{ color: #1976d2; font-weight: bold; }}
        .remediation {{ background: #e8f5e9; padding: 15px; border-radius: 8px;
                        margin: 10px 0; border-left: 4px solid #4caf50; }}
        .timestamp {{ color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Error Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

        <div class="summary-cards">
            <div class="card error">
                <h3>Total Errors</h3>
                <div class="value">{analysis['total_errors']}</div>
            </div>
            <div class="card">
                <h3>Error Rate</h3>
                <div class="value">{analysis['error_rate']}%</div>
            </div>
            <div class="card">
                <h3>Total Logs Analyzed</h3>
                <div class="value">{analysis['total_logs']}</div>
            </div>
        </div>

        <h2>Errors by HTTP Status Code</h2>
        <table>
            <tr><th>Status Code</th><th>Count</th><th>Description</th></tr>
            {''.join(f'<tr><td class="status-{code}">{code}</td><td>{count}</td><td>{get_status_description(code)}</td></tr>'
                     for code, count in analysis['by_status_code'].items())}
        </table>

        <h2>Errors by Service</h2>
        <table>
            <tr><th>Service</th><th>Error Count</th></tr>
            {''.join(f'<tr><td>{service}</td><td>{count}</td></tr>'
                     for service, count in analysis['by_service'].items())}
        </table>

        <h2>Errors by Message Type</h2>
        <table>
            <tr><th>Error Message</th><th>Count</th></tr>
            {''.join(f'<tr><td>{msg}</td><td>{count}</td></tr>'
                     for msg, count in analysis['by_message'].items())}
        </table>

        <h2>Error Distribution by Hour</h2>
        <table>
            <tr><th>Hour (UTC)</th><th>Error Count</th></tr>
            {''.join(f'<tr><td>{hour}:00</td><td>{count}</td></tr>'
                     for hour, count in analysis['by_hour'].items())}
        </table>

        <h2>Root Cause Analysis & Remediation</h2>
        {''.join(f'''<div class="remediation">
            <strong>{rc['error_message']}</strong> ({rc['count']} occurrences)<br>
            <strong>Root Cause:</strong> {rc['root_cause']}<br>
            <strong>Remediation:</strong> {rc['remediation']}
        </div>''' for rc in analysis['root_causes'])}

        <h2>Error Cascades Detected</h2>
        <table>
            <tr><th>Trigger Service</th><th>Affected Service</th><th>Trigger Message</th></tr>
            {''.join(f'<tr><td>{c["trigger_service"]}</td><td>{c["affected_service"]}</td><td>{c["trigger_message"]}</td></tr>'
                     for c in analysis['error_cascades'][:10])}
        </table>

        <h2>Recent Error Details</h2>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Status</th><th>Endpoint</th><th>Response Time</th></tr>
            {''.join(f'<tr><td>{e["timestamp"]}</td><td>{e["service"]}</td><td class="status-{e["status_code"]}">{e["status_code"]}</td><td>{e["endpoint"]}</td><td>{e["response_time_ms"]}ms</td></tr>'
                     for e in analysis['error_details'][:20])}
        </table>
    </div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_security_html_report(analysis: dict[str, Any], output_path: str) -> None:
    """Generate HTML report for security analysis.

    Args:
        analysis: Security analysis results.
        output_path: Path to save the HTML report.
    """
    severity = analysis['severity_classification']

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #c62828; border-bottom: 3px solid #c62828; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                         gap: 20px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 8px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card.critical {{ border-left: 4px solid #b71c1c; }}
        .card.high {{ border-left: 4px solid #d32f2f; }}
        .card.medium {{ border-left: 4px solid #f57c00; }}
        .card.low {{ border-left: 4px solid #fbc02d; }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .card .value {{ font-size: 32px; font-weight: bold; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f8f8; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .severity-critical {{ background: #ffebee; color: #b71c1c; font-weight: bold; }}
        .severity-high {{ background: #fff3e0; color: #e65100; font-weight: bold; }}
        .severity-medium {{ background: #fff8e1; color: #f57f17; font-weight: bold; }}
        .severity-low {{ background: #f1f8e9; color: #558b2f; }}
        .alert {{ padding: 15px; border-radius: 8px; margin: 10px 0; }}
        .alert-critical {{ background: #ffebee; border-left: 4px solid #b71c1c; }}
        .alert-high {{ background: #fff3e0; border-left: 4px solid #e65100; }}
        .timestamp {{ color: #666; font-size: 12px; }}
        .ip-badge {{ background: #e3f2fd; padding: 2px 8px; border-radius: 4px;
                     font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

        <div class="summary-cards">
            <div class="card critical">
                <h3>Critical Issues</h3>
                <div class="value">{len(severity['critical'])}</div>
            </div>
            <div class="card high">
                <h3>High Severity</h3>
                <div class="value">{len(severity['high'])}</div>
            </div>
            <div class="card medium">
                <h3>Medium Severity</h3>
                <div class="value">{len(severity['medium'])}</div>
            </div>
            <div class="card low">
                <h3>Low Severity</h3>
                <div class="value">{len(severity['low'])}</div>
            </div>
        </div>

        <h2>Critical Security Issues</h2>
        {''.join(f'''<div class="alert alert-critical">
            <strong>{item['type']}</strong><br>
            IP: <span class="ip-badge">{item['details'].get('ip', 'N/A')}</span><br>
            Payload: <code>{item['details'].get('payload', 'N/A')}</code><br>
            <strong>Recommendation:</strong> {item['recommendation']}
        </div>''' for item in severity['critical'])}

        <h2>High Severity Issues</h2>
        {''.join(f'''<div class="alert alert-high">
            <strong>{item['type']}</strong><br>
            {'IP: <span class="ip-badge">' + item['details'].get('ip', 'N/A') + '</span><br>' if 'ip' in item['details'] else ''}
            <strong>Recommendation:</strong> {item['recommendation']}
        </div>''' for item in severity['high'])}

        <h2>SQL Injection Attempts</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Payload</th><th>User Agent</th></tr>
            {''.join(f'<tr class="severity-critical"><td>{a["timestamp"]}</td><td class="ip-badge">{a["ip"]}</td><td>{a["endpoint"]}</td><td><code>{a["payload"]}</code></td><td>{a["user_agent"]}</td></tr>'
                     for a in analysis['injection_attempts']['details'])}
        </table>

        <h2>XSS Attempts</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Payload</th></tr>
            {''.join(f'<tr class="severity-high"><td>{a["timestamp"]}</td><td class="ip-badge">{a["ip"]}</td><td>{a["endpoint"]}</td><td><code>{html_escape(str(a["payload"]))}</code></td></tr>'
                     for a in analysis['xss_attempts']['details'])}
        </table>

        <h2>Authentication Failures</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Attempts</th><th>User Agent</th></tr>
            {''.join(f'<tr><td>{a["timestamp"]}</td><td class="ip-badge">{a["ip"]}</td><td>{a["endpoint"]}</td><td>{a["attempts"]}</td><td>{a["user_agent"]}</td></tr>'
                     for a in analysis['auth_failures']['details'])}
        </table>

        <h2>Suspicious IPs</h2>
        <table>
            <tr><th>IP Address</th><th>Failure Count</th><th>Event Types</th></tr>
            {''.join(f'<tr><td class="ip-badge">{ip["ip"]}</td><td>{ip["failure_count"]}</td><td>{", ".join(set(e["event_type"] for e in ip["events"]))}</td></tr>'
                     for ip in analysis['suspicious_ips'])}
        </table>

        <h2>Suspicious User Agents (Attack Tools)</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Tool Detected</th><th>User Agent</th></tr>
            {''.join(f'<tr class="severity-high"><td>{ua["timestamp"]}</td><td class="ip-badge">{ua["ip"]}</td><td>{ua["tool_detected"]}</td><td>{ua["user_agent"]}</td></tr>'
                     for ua in analysis['suspicious_user_agents'])}
        </table>

        <h2>Rate Limit Violations</h2>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Requests/Min</th><th>Endpoint</th></tr>
            {''.join(f'<tr><td>{v["timestamp"]}</td><td class="ip-badge">{v["ip"]}</td><td>{v["requests_per_minute"]}</td><td>{v["endpoint"]}</td></tr>'
                     for v in analysis['rate_limit_violations']['details'])}
        </table>
    </div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_performance_html_report(analysis: dict[str, Any], output_path: str) -> None:
    """Generate HTML report for performance analysis.

    Args:
        analysis: Performance analysis results.
        output_path: Path to save the HTML report.
    """
    stats = analysis['overall_stats']

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Analysis Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #1565c0; border-bottom: 3px solid #1565c0; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                         gap: 20px; margin: 20px 0; }}
        .card {{ background: white; padding: 20px; border-radius: 8px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card.highlight {{ border-left: 4px solid #1565c0; }}
        .card.warning {{ border-left: 4px solid #f57c00; }}
        .card h3 {{ margin: 0 0 10px 0; color: #666; font-size: 14px; }}
        .card .value {{ font-size: 24px; font-weight: bold; color: #333; }}
        .card .unit {{ font-size: 14px; color: #666; }}
        table {{ width: 100%; border-collapse: collapse; background: white;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f8f8; font-weight: 600; }}
        tr:hover {{ background: #f5f5f5; }}
        .slow {{ color: #d32f2f; font-weight: bold; }}
        .warning-box {{ background: #fff3e0; padding: 15px; border-radius: 8px;
                        margin: 10px 0; border-left: 4px solid #f57c00; }}
        .insight {{ background: #e3f2fd; padding: 15px; border-radius: 8px;
                    margin: 10px 0; border-left: 4px solid #1565c0; }}
        .timestamp {{ color: #666; font-size: 12px; }}
        .progress-bar {{ background: #e0e0e0; border-radius: 4px; height: 20px; }}
        .progress-fill {{ background: #1565c0; border-radius: 4px; height: 100%; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Performance Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

        <h2>Response Time Overview</h2>
        <div class="summary-cards">
            <div class="card highlight">
                <h3>Average</h3>
                <div class="value">{stats['avg']}<span class="unit">ms</span></div>
            </div>
            <div class="card">
                <h3>Median</h3>
                <div class="value">{stats['median']}<span class="unit">ms</span></div>
            </div>
            <div class="card">
                <h3>P95</h3>
                <div class="value">{stats['p95']}<span class="unit">ms</span></div>
            </div>
            <div class="card warning">
                <h3>P99</h3>
                <div class="value">{stats['p99']}<span class="unit">ms</span></div>
            </div>
            <div class="card">
                <h3>Min</h3>
                <div class="value">{stats['min']}<span class="unit">ms</span></div>
            </div>
            <div class="card warning">
                <h3>Max</h3>
                <div class="value">{stats['max']}<span class="unit">ms</span></div>
            </div>
        </div>

        <h2>Slow Requests (>{analysis['slow_requests']['threshold_ms']}ms)</h2>
        <div class="card warning">
            <h3>Total Slow Requests</h3>
            <div class="value">{analysis['slow_requests']['count']}</div>
        </div>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Endpoint</th><th>Response Time</th><th>Status</th></tr>
            {''.join(f'<tr><td>{r["timestamp"]}</td><td>{r["service"]}</td><td>{r["endpoint"]}</td><td class="slow">{r["response_time_ms"]}ms</td><td>{r["status_code"]}</td></tr>'
                     for r in analysis['slow_requests']['details'][:15])}
        </table>

        <h2>Performance by Endpoint</h2>
        <table>
            <tr><th>Endpoint</th><th>Requests</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Max (ms)</th></tr>
            {''.join(f'<tr><td>{endpoint}</td><td>{s["count"]}</td><td>{s["avg"]}</td><td>{s["p95"]}</td><td>{s["p99"]}</td><td class="{"slow" if s["max"] > 1000 else ""}">{s["max"]}</td></tr>'
                     for endpoint, s in sorted(analysis['endpoint_stats'].items(), key=lambda x: x[1]['avg'], reverse=True))}
        </table>

        <h2>Performance by Service</h2>
        <table>
            <tr><th>Service</th><th>Requests</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th></tr>
            {''.join(f'<tr><td>{service}</td><td>{s["count"]}</td><td>{s["avg"]}</td><td>{s["p95"]}</td><td>{s["p99"]}</td></tr>'
                     for service, s in sorted(analysis['service_stats'].items(), key=lambda x: x[1]['avg'], reverse=True))}
        </table>

        <h2>Hourly Performance Trends</h2>
        <table>
            <tr><th>Hour (UTC)</th><th>Requests</th><th>Avg (ms)</th><th>P95 (ms)</th></tr>
            {''.join(f'<tr><td>{hour}:00</td><td>{s["count"]}</td><td>{s["avg"]}</td><td>{s["p95"]}</td></tr>'
                     for hour, s in analysis['hourly_stats'].items())}
        </table>

        <h2>Resource Utilization Warnings</h2>

        <h3>Connection Pool Warnings ({len(analysis['resource_utilization']['connection_pool_warnings'])})</h3>
        {''.join(f'''<div class="warning-box">
            <strong>{w["service"]}</strong> at {w["timestamp"]}<br>
            Active: {w["active_connections"]}/{w["max_connections"]} connections, Wait time: {w["wait_time_ms"]}ms
        </div>''' for w in analysis['resource_utilization']['connection_pool_warnings'])}

        <h3>Memory Warnings ({len(analysis['resource_utilization']['memory_warnings'])})</h3>
        {''.join(f'''<div class="warning-box">
            <strong>{w["service"]}</strong> at {w["timestamp"]}<br>
            Memory: {w["memory_used_mb"]}/{w["memory_limit_mb"]} MB, GC Pause: {w["gc_pause_ms"]}ms
        </div>''' for w in analysis['resource_utilization']['memory_warnings'])}

        <h3>Disk I/O Warnings ({len(analysis['resource_utilization']['disk_io_warnings'])})</h3>
        {''.join(f'''<div class="warning-box">
            <strong>{w["service"]}</strong> at {w["timestamp"]}<br>
            Read Latency: {w["read_latency_ms"]}ms, Write Latency: {w["write_latency_ms"]}ms, IOPS: {w["iops"]}
        </div>''' for w in analysis['resource_utilization']['disk_io_warnings'])}

        <h2>Capacity Planning Insights</h2>
        <h3>Peak Load Hours</h3>
        {''.join(f'''<div class="insight">
            <strong>{p["hour"]}:00 UTC</strong> - Average response time: {p["avg_response_time"]}ms
        </div>''' for p in analysis['capacity_insights']['peak_hours'])}

        <h3>Recommendations</h3>
        {''.join(f'''<div class="warning-box">
            <strong>{r["area"]}</strong> ({r["severity"]})<br>
            {r["recommendation"]}
        </div>''' for r in analysis['capacity_insights']['recommendations'])}
    </div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_summary_html_report(
    error_analysis: dict[str, Any],
    security_analysis: dict[str, Any],
    performance_analysis: dict[str, Any],
    output_path: str
) -> None:
    """Generate summary HTML report combining all analyses.

    Args:
        error_analysis: Error analysis results.
        security_analysis: Security analysis results.
        performance_analysis: Performance analysis results.
        output_path: Path to save the HTML report.
    """
    severity = security_analysis['severity_classification']
    perf_stats = performance_analysis['overall_stats']

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elastic Logs Analysis Summary</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #333; border-bottom: 3px solid #333; padding-bottom: 10px; }}
        h2 {{ color: #333; margin-top: 30px; }}
        .section {{ background: white; padding: 20px; border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }}
        .section.error {{ border-top: 4px solid #d32f2f; }}
        .section.security {{ border-top: 4px solid #c62828; }}
        .section.performance {{ border-top: 4px solid #1565c0; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                         gap: 15px; margin: 15px 0; }}
        .card {{ background: #f8f8f8; padding: 15px; border-radius: 8px; text-align: center; }}
        .card h4 {{ margin: 0 0 5px 0; color: #666; font-size: 12px; }}
        .card .value {{ font-size: 24px; font-weight: bold; }}
        .card .value.error {{ color: #d32f2f; }}
        .card .value.warning {{ color: #f57c00; }}
        .card .value.success {{ color: #388e3c; }}
        .card .value.info {{ color: #1565c0; }}
        .links {{ margin-top: 20px; }}
        .links a {{ display: inline-block; padding: 10px 20px; background: #1565c0;
                    color: white; text-decoration: none; border-radius: 4px; margin: 5px; }}
        .links a:hover {{ background: #0d47a1; }}
        .timestamp {{ color: #666; font-size: 12px; }}
        .key-findings {{ background: #fff8e1; padding: 15px; border-radius: 8px;
                         border-left: 4px solid #ffc107; margin: 15px 0; }}
        ul {{ margin: 10px 0; padding-left: 20px; }}
        li {{ margin: 5px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Elastic Logs Analysis Summary</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p>Log file: logs/elastic_logs_30_11_25.json | Total entries: {error_analysis['total_logs']}</p>

        <div class="section error">
            <h2>Error Analysis</h2>
            <div class="summary-cards">
                <div class="card">
                    <h4>Total Errors</h4>
                    <div class="value error">{error_analysis['total_errors']}</div>
                </div>
                <div class="card">
                    <h4>Error Rate</h4>
                    <div class="value warning">{error_analysis['error_rate']}%</div>
                </div>
                <div class="card">
                    <h4>Unique Error Types</h4>
                    <div class="value info">{len(error_analysis['by_message'])}</div>
                </div>
                <div class="card">
                    <h4>Affected Services</h4>
                    <div class="value info">{len(error_analysis['by_service'])}</div>
                </div>
            </div>
            <div class="key-findings">
                <strong>Key Findings:</strong>
                <ul>
                    <li>Most common error: {list(error_analysis['by_message'].keys())[0] if error_analysis['by_message'] else 'N/A'}</li>
                    <li>Most affected service: {list(error_analysis['by_service'].keys())[0] if error_analysis['by_service'] else 'N/A'}</li>
                    <li>Error cascades detected: {len(error_analysis['error_cascades'])}</li>
                </ul>
            </div>
        </div>

        <div class="section security">
            <h2>Security Analysis</h2>
            <div class="summary-cards">
                <div class="card">
                    <h4>Critical Issues</h4>
                    <div class="value error">{len(severity['critical'])}</div>
                </div>
                <div class="card">
                    <h4>High Severity</h4>
                    <div class="value warning">{len(severity['high'])}</div>
                </div>
                <div class="card">
                    <h4>SQL Injection Attempts</h4>
                    <div class="value error">{security_analysis['injection_attempts']['sql_injection_count']}</div>
                </div>
                <div class="card">
                    <h4>Suspicious IPs</h4>
                    <div class="value warning">{len(security_analysis['suspicious_ips'])}</div>
                </div>
            </div>
            <div class="key-findings">
                <strong>Key Findings:</strong>
                <ul>
                    <li>Total security events: {security_analysis['total_security_events']}</li>
                    <li>Authentication failures: {security_analysis['auth_failures']['count']}</li>
                    <li>XSS attempts: {security_analysis['xss_attempts']['count']}</li>
                    <li>Rate limit violations: {security_analysis['rate_limit_violations']['count']}</li>
                    <li>Attack tools detected: {len(security_analysis['suspicious_user_agents'])}</li>
                </ul>
            </div>
        </div>

        <div class="section performance">
            <h2>Performance Analysis</h2>
            <div class="summary-cards">
                <div class="card">
                    <h4>Avg Response Time</h4>
                    <div class="value info">{perf_stats['avg']}ms</div>
                </div>
                <div class="card">
                    <h4>P95 Response Time</h4>
                    <div class="value warning">{perf_stats['p95']}ms</div>
                </div>
                <div class="card">
                    <h4>P99 Response Time</h4>
                    <div class="value error">{perf_stats['p99']}ms</div>
                </div>
                <div class="card">
                    <h4>Slow Requests</h4>
                    <div class="value warning">{performance_analysis['slow_requests']['count']}</div>
                </div>
            </div>
            <div class="key-findings">
                <strong>Key Findings:</strong>
                <ul>
                    <li>Max response time: {perf_stats['max']}ms</li>
                    <li>Connection pool warnings: {len(performance_analysis['resource_utilization']['connection_pool_warnings'])}</li>
                    <li>Memory warnings: {len(performance_analysis['resource_utilization']['memory_warnings'])}</li>
                    <li>Disk I/O warnings: {len(performance_analysis['resource_utilization']['disk_io_warnings'])}</li>
                </ul>
            </div>
        </div>

        <div class="links">
            <h2>Detailed Reports</h2>
            <a href="error_analysis_report.html">Error Analysis Report</a>
            <a href="security_analysis_report.html">Security Analysis Report</a>
            <a href="performance_analysis_report.html">Performance Analysis Report</a>
        </div>
    </div>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def get_status_description(code: int) -> str:
    """Get description for HTTP status code.

    Args:
        code: HTTP status code.

    Returns:
        Description of the status code.
    """
    descriptions = {
        500: 'Internal Server Error',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout'
    }
    return descriptions.get(code, 'Unknown Error')


def html_escape(text: str) -> str:
    """Escape HTML special characters.

    Args:
        text: Text to escape.

    Returns:
        HTML-escaped text.
    """
    return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&#39;'))


def main() -> None:
    """Main entry point for the analysis script."""
    import argparse

    parser = argparse.ArgumentParser(description='Analyze Elastic logs')
    parser.add_argument('--log-file', default='logs/elastic_logs.json',
                        help='Path to the log file')
    parser.add_argument('--output-dir', default='analysis',
                        help='Directory to save reports')
    args = parser.parse_args()

    print(f"Loading logs from {args.log_file}...")
    logs = load_logs(args.log_file)
    print(f"Loaded {len(logs)} log entries")

    os.makedirs(args.output_dir, exist_ok=True)

    print("\n[Task 1] Running Error Pattern Analysis...")
    error_results = analyze_errors(logs)
    print(f"  - Found {error_results['total_errors']} errors ({error_results['error_rate']}% error rate)")
    print(f"  - {len(error_results['by_service'])} services affected")
    print(f"  - {len(error_results['root_causes'])} root causes identified")

    print("\n[Task 2] Running Security Issue Detection...")
    security_results = analyze_security(logs)
    severity = security_results['severity_classification']
    print(f"  - {len(severity['critical'])} critical issues")
    print(f"  - {len(severity['high'])} high severity issues")
    print(f"  - {security_results['injection_attempts']['sql_injection_count']} SQL injection attempts")
    print(f"  - {len(security_results['suspicious_ips'])} suspicious IPs")

    print("\n[Task 3] Running Performance Anomaly Analysis...")
    performance_results = analyze_performance(logs)
    stats = performance_results['overall_stats']
    print(f"  - Avg response time: {stats['avg']}ms")
    print(f"  - P95: {stats['p95']}ms, P99: {stats['p99']}ms")
    print(f"  - {performance_results['slow_requests']['count']} slow requests (>1000ms)")

    print("\nGenerating HTML reports...")
    generate_error_html_report(
        error_results,
        os.path.join(args.output_dir, 'error_analysis_report.html')
    )
    print(f"  - Saved: {args.output_dir}/error_analysis_report.html")

    generate_security_html_report(
        security_results,
        os.path.join(args.output_dir, 'security_analysis_report.html')
    )
    print(f"  - Saved: {args.output_dir}/security_analysis_report.html")

    generate_performance_html_report(
        performance_results,
        os.path.join(args.output_dir, 'performance_analysis_report.html')
    )
    print(f"  - Saved: {args.output_dir}/performance_analysis_report.html")

    generate_summary_html_report(
        error_results,
        security_results,
        performance_results,
        os.path.join(args.output_dir, 'analysis_summary.html')
    )
    print(f"  - Saved: {args.output_dir}/analysis_summary.html")

    print("\nAnalysis complete!")


if __name__ == '__main__':
    main()
