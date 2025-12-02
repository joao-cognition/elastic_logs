#!/usr/bin/env python3
"""Comprehensive Elastic Logs Analysis Script.

This script performs three types of analysis on Elastic logs:
1. Error Pattern Analysis
2. Security Issue Detection
3. Performance Anomaly Analysis

It generates HTML reports for each analysis type plus a summary report.
"""

import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean, median, stdev
from typing import Any

# Type aliases for clarity
LogEntry = dict[str, Any]
LogData = list[LogEntry]


def load_logs(file_path: str) -> LogData:
    """Load and parse JSON log file.

    Args:
        file_path: Path to the JSON log file.

    Returns:
        List of log entry dictionaries.

    Raises:
        FileNotFoundError: If the log file doesn't exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
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
    index = (len(sorted_data) - 1) * percentile / 100
    lower = int(index)
    upper = lower + 1
    if upper >= len(sorted_data):
        return sorted_data[-1]
    weight = index - lower
    return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight


def analyze_errors(logs: LogData) -> dict[str, Any]:
    """Perform comprehensive error pattern analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing error analysis results.
    """
    error_logs = [log for log in logs if log.get('level') == 'ERROR']
    all_logs_with_status = [log for log in logs if log.get('http', {}).get('status_code')]

    # Error frequency by status code
    status_code_counts: Counter[int] = Counter()
    for log in all_logs_with_status:
        status_code = log['http']['status_code']
        if status_code >= 400:
            status_code_counts[status_code] += 1

    # Errors by service
    errors_by_service: Counter[str] = Counter()
    for log in error_logs:
        errors_by_service[log.get('service', 'unknown')] += 1

    # Error message types
    error_message_types: Counter[str] = Counter()
    for log in error_logs:
        error_message_types[log.get('message', 'unknown')] += 1

    # Error types from error field
    error_types: Counter[str] = Counter()
    for log in error_logs:
        if 'error' in log:
            error_types[log['error'].get('type', 'unknown')] += 1

    # Errors by endpoint
    errors_by_endpoint: Counter[str] = Counter()
    for log in error_logs:
        endpoint = log.get('http', {}).get('endpoint', 'unknown')
        errors_by_endpoint[endpoint] += 1

    # Time-based analysis
    errors_by_hour: Counter[int] = Counter()
    for log in error_logs:
        timestamp = log.get('@timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                errors_by_hour[dt.hour] += 1
            except ValueError:
                pass

    # Error cascades (errors within 5 minutes of each other from different services)
    error_cascades: list[dict[str, Any]] = []
    sorted_errors = sorted(error_logs, key=lambda x: x.get('@timestamp', ''))
    for i, error in enumerate(sorted_errors[:-1]):
        next_error = sorted_errors[i + 1]
        try:
            t1 = datetime.fromisoformat(error.get('@timestamp', '').replace('Z', '+00:00'))
            t2 = datetime.fromisoformat(next_error.get('@timestamp', '').replace('Z', '+00:00'))
            time_diff = (t2 - t1).total_seconds()
            if time_diff <= 300 and error.get('service') != next_error.get('service'):
                error_cascades.append({
                    'first_error': error.get('log_id'),
                    'second_error': next_error.get('log_id'),
                    'first_service': error.get('service'),
                    'second_service': next_error.get('service'),
                    'time_diff_seconds': time_diff
                })
        except (ValueError, TypeError):
            pass

    # Root cause analysis based on error messages
    root_causes: list[dict[str, Any]] = []
    for message, count in error_message_types.most_common():
        cause = {
            'error_message': message,
            'count': count,
            'potential_cause': '',
            'remediation': ''
        }
        if 'timeout' in message.lower() or 'unavailable' in message.lower():
            cause['potential_cause'] = 'Upstream service unavailability or network issues'
            cause['remediation'] = 'Check upstream service health, increase timeout values, implement circuit breakers'
        elif 'connection pool' in message.lower() or 'database' in message.lower():
            cause['potential_cause'] = 'Database connection pool exhaustion'
            cause['remediation'] = 'Increase connection pool size, optimize query performance, implement connection pooling'
        elif 'null' in message.lower() or 'NullPointer' in message.lower():
            cause['potential_cause'] = 'Null reference in application code'
            cause['remediation'] = 'Add null checks, review code for null safety'
        elif 'memory' in message.lower() or 'OutOfMemory' in message.lower():
            cause['potential_cause'] = 'Memory exhaustion'
            cause['remediation'] = 'Increase heap size, fix memory leaks, optimize memory usage'
        else:
            cause['potential_cause'] = 'Application-level error'
            cause['remediation'] = 'Review application logs and stack traces for detailed debugging'
        root_causes.append(cause)

    # Impact assessment
    total_requests = len(all_logs_with_status)
    total_errors = len(error_logs)
    error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0

    return {
        'summary': {
            'total_logs': len(logs),
            'total_errors': total_errors,
            'error_rate_percent': round(error_rate, 2),
            'unique_error_messages': len(error_message_types)
        },
        'status_code_distribution': dict(status_code_counts.most_common()),
        'errors_by_service': dict(errors_by_service.most_common()),
        'error_message_types': dict(error_message_types.most_common()),
        'error_types': dict(error_types.most_common()),
        'errors_by_endpoint': dict(errors_by_endpoint.most_common()),
        'errors_by_hour': dict(sorted(errors_by_hour.items())),
        'error_cascades': error_cascades[:10],
        'root_causes': root_causes,
        'most_affected_services': list(errors_by_service.most_common(5)),
        'highest_error_endpoints': list(errors_by_endpoint.most_common(5))
    }


def analyze_security(logs: LogData) -> dict[str, Any]:
    """Perform comprehensive security issue detection.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing security analysis results.
    """
    # Authentication failures (401 status codes)
    auth_failures = [log for log in logs if log.get('http', {}).get('status_code') == 401]

    # Failed logins by IP
    failed_login_by_ip: Counter[str] = Counter()
    for log in auth_failures:
        ip = log.get('client', {}).get('ip', 'unknown')
        failed_login_by_ip[ip] += 1

    # Brute force detection (IPs with > 3 failed attempts)
    brute_force_ips = {ip: count for ip, count in failed_login_by_ip.items() if count > 3}

    # Suspicious user agents
    suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan', 'dirbuster', 'gobuster', 'wfuzz']
    suspicious_ua_logs: list[dict[str, Any]] = []
    for log in logs:
        ua = log.get('client', {}).get('user_agent', '').lower()
        for agent in suspicious_agents:
            if agent in ua:
                suspicious_ua_logs.append({
                    'log_id': log.get('log_id'),
                    'timestamp': log.get('@timestamp'),
                    'ip': log.get('client', {}).get('ip'),
                    'user_agent': log.get('client', {}).get('user_agent'),
                    'endpoint': log.get('http', {}).get('endpoint'),
                    'tool_detected': agent
                })
                break

    # SQL injection attempts
    sql_injection_logs: list[dict[str, Any]] = []
    sql_patterns = ["' OR", "1=1", "UNION SELECT", "DROP TABLE", "--", "/*", "*/"]
    for log in logs:
        security_info = log.get('security', {})
        message = log.get('message', '').lower()
        if security_info.get('event_type') == 'SQL_INJECTION_ATTEMPT':
            sql_injection_logs.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'payload': security_info.get('payload', ''),
                'endpoint': log.get('http', {}).get('endpoint')
            })
        elif 'sql injection' in message:
            sql_injection_logs.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'payload': 'Detected in message',
                'endpoint': log.get('http', {}).get('endpoint')
            })

    # XSS attempts
    xss_logs: list[dict[str, Any]] = []
    for log in logs:
        security_info = log.get('security', {})
        message = log.get('message', '').lower()
        if security_info.get('event_type') == 'XSS_ATTEMPT':
            xss_logs.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'payload': security_info.get('payload', ''),
                'endpoint': log.get('http', {}).get('endpoint')
            })
        elif 'xss' in message or 'cross-site' in message:
            xss_logs.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'payload': 'Detected in message',
                'endpoint': log.get('http', {}).get('endpoint')
            })

    # Access control violations (403 status codes)
    access_violations = [log for log in logs if log.get('http', {}).get('status_code') == 403]

    # Unauthorized access attempts
    unauthorized_access: list[dict[str, Any]] = []
    for log in logs:
        security_info = log.get('security', {})
        if security_info.get('event_type') == 'UNAUTHORIZED_ACCESS':
            unauthorized_access.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'target_resource': security_info.get('target_resource', ''),
                'endpoint': log.get('http', {}).get('endpoint')
            })

    # Rate limit violations
    rate_limit_violations: list[dict[str, Any]] = []
    for log in logs:
        security_info = log.get('security', {})
        message = log.get('message', '').lower()
        if security_info.get('event_type') == 'RATE_LIMIT_EXCEEDED' or 'rate limit' in message:
            rate_limit_violations.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'requests_per_minute': security_info.get('requests_per_minute', 'N/A'),
                'endpoint': log.get('http', {}).get('endpoint')
            })

    # IPs with high failure rates
    ip_failure_rates: dict[str, dict[str, int]] = defaultdict(lambda: {'total': 0, 'failures': 0})
    for log in logs:
        ip = log.get('client', {}).get('ip', 'unknown')
        status_code = log.get('http', {}).get('status_code', 0)
        ip_failure_rates[ip]['total'] += 1
        if status_code >= 400:
            ip_failure_rates[ip]['failures'] += 1

    high_failure_ips = {
        ip: {'total': data['total'], 'failures': data['failures'],
             'rate': round(data['failures'] / data['total'] * 100, 2)}
        for ip, data in ip_failure_rates.items()
        if data['total'] >= 5 and data['failures'] / data['total'] > 0.5
    }

    # User agent analysis
    user_agent_counts: Counter[str] = Counter()
    for log in logs:
        ua = log.get('client', {}).get('user_agent', 'unknown')
        user_agent_counts[ua] += 1

    # Severity classification
    critical_findings: list[str] = []
    high_findings: list[str] = []
    medium_findings: list[str] = []
    low_findings: list[str] = []

    if sql_injection_logs:
        critical_findings.append(f"SQL Injection attempts detected: {len(sql_injection_logs)} incidents")
    if xss_logs:
        critical_findings.append(f"XSS attempts detected: {len(xss_logs)} incidents")
    if brute_force_ips:
        high_findings.append(f"Brute force attack patterns from {len(brute_force_ips)} IPs")
    if suspicious_ua_logs:
        high_findings.append(f"Attack tools detected: {len(suspicious_ua_logs)} requests")
    if unauthorized_access:
        high_findings.append(f"Unauthorized access attempts: {len(unauthorized_access)} incidents")
    if high_failure_ips:
        medium_findings.append(f"IPs with high failure rates: {len(high_failure_ips)}")
    if rate_limit_violations:
        medium_findings.append(f"Rate limit violations: {len(rate_limit_violations)} incidents")
    if auth_failures:
        low_findings.append(f"Authentication failures: {len(auth_failures)} incidents")

    return {
        'summary': {
            'total_security_events': (len(sql_injection_logs) + len(xss_logs) + len(unauthorized_access) +
                                      len(rate_limit_violations) + len(auth_failures)),
            'critical_count': len(critical_findings),
            'high_count': len(high_findings),
            'medium_count': len(medium_findings),
            'low_count': len(low_findings)
        },
        'authentication': {
            'total_failures': len(auth_failures),
            'failures_by_ip': dict(failed_login_by_ip.most_common(10)),
            'brute_force_ips': brute_force_ips
        },
        'injection_attacks': {
            'sql_injection': sql_injection_logs,
            'xss_attempts': xss_logs
        },
        'access_control': {
            'total_403_responses': len(access_violations),
            'unauthorized_access_attempts': unauthorized_access
        },
        'rate_limiting': {
            'violations': rate_limit_violations,
            'total_violations': len(rate_limit_violations)
        },
        'suspicious_activity': {
            'attack_tools_detected': suspicious_ua_logs,
            'high_failure_ips': high_failure_ips
        },
        'user_agents': {
            'distribution': dict(user_agent_counts.most_common(10)),
            'suspicious_count': len(suspicious_ua_logs)
        },
        'severity_classification': {
            'critical': critical_findings,
            'high': high_findings,
            'medium': medium_findings,
            'low': low_findings
        }
    }


def analyze_performance(logs: LogData) -> dict[str, Any]:
    """Perform comprehensive performance anomaly analysis.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing performance analysis results.
    """
    # Response time analysis
    response_times: list[float] = []
    response_times_by_endpoint: dict[str, list[float]] = defaultdict(list)
    response_times_by_service: dict[str, list[float]] = defaultdict(list)

    for log in logs:
        rt = log.get('http', {}).get('response_time_ms')
        if rt is not None:
            response_times.append(rt)
            endpoint = log.get('http', {}).get('endpoint', 'unknown')
            service = log.get('service', 'unknown')
            response_times_by_endpoint[endpoint].append(rt)
            response_times_by_service[service].append(rt)

    # Calculate statistics
    def calc_stats(times: list[float]) -> dict[str, float]:
        if not times:
            return {'min': 0, 'max': 0, 'avg': 0, 'median': 0, 'p95': 0, 'p99': 0, 'std_dev': 0}
        return {
            'min': round(min(times), 2),
            'max': round(max(times), 2),
            'avg': round(mean(times), 2),
            'median': round(median(times), 2),
            'p95': round(calculate_percentile(times, 95), 2),
            'p99': round(calculate_percentile(times, 99), 2),
            'std_dev': round(stdev(times), 2) if len(times) > 1 else 0
        }

    overall_stats = calc_stats(response_times)

    endpoint_stats = {
        endpoint: calc_stats(times)
        for endpoint, times in response_times_by_endpoint.items()
    }

    service_stats = {
        service: calc_stats(times)
        for service, times in response_times_by_service.items()
    }

    # Slow endpoints (avg > 1000ms)
    slow_endpoints = {
        endpoint: stats
        for endpoint, stats in endpoint_stats.items()
        if stats['avg'] > 1000
    }

    # Response time spikes (> 10000ms)
    response_time_spikes: list[dict[str, Any]] = []
    for log in logs:
        rt = log.get('http', {}).get('response_time_ms', 0)
        if rt > 10000:
            response_time_spikes.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'service': log.get('service'),
                'endpoint': log.get('http', {}).get('endpoint'),
                'response_time_ms': rt
            })

    # Resource utilization analysis
    disk_io_issues: list[dict[str, Any]] = []
    memory_issues: list[dict[str, Any]] = []
    connection_pool_issues: list[dict[str, Any]] = []

    for log in logs:
        performance = log.get('performance', {})
        message = log.get('message', '').lower()

        if performance.get('read_latency_ms') or performance.get('write_latency_ms'):
            disk_io_issues.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'service': log.get('service'),
                'read_latency_ms': performance.get('read_latency_ms'),
                'write_latency_ms': performance.get('write_latency_ms'),
                'iops': performance.get('iops')
            })

        if 'memory' in message or performance.get('memory_usage_percent'):
            memory_issues.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'service': log.get('service'),
                'message': log.get('message'),
                'memory_usage_percent': performance.get('memory_usage_percent')
            })

        if 'connection pool' in message:
            connection_pool_issues.append({
                'log_id': log.get('log_id'),
                'timestamp': log.get('@timestamp'),
                'service': log.get('service'),
                'message': log.get('message')
            })

    # Database performance (slow queries, timeouts)
    database_issues: list[dict[str, Any]] = []
    for log in logs:
        message = log.get('message', '').lower()
        if 'database' in message or 'query' in message or 'sql' in message:
            if 'slow' in message or 'timeout' in message or 'exhausted' in message:
                database_issues.append({
                    'log_id': log.get('log_id'),
                    'timestamp': log.get('@timestamp'),
                    'service': log.get('service'),
                    'message': log.get('message')
                })

    # Service health analysis
    service_error_rates: dict[str, dict[str, int]] = defaultdict(lambda: {'total': 0, 'errors': 0})
    for log in logs:
        service = log.get('service', 'unknown')
        service_error_rates[service]['total'] += 1
        if log.get('level') == 'ERROR':
            service_error_rates[service]['errors'] += 1

    service_health = {
        service: {
            'total_requests': data['total'],
            'errors': data['errors'],
            'error_rate': round(data['errors'] / data['total'] * 100, 2) if data['total'] > 0 else 0,
            'health_status': 'HEALTHY' if data['errors'] / data['total'] < 0.05 else
                            'DEGRADED' if data['errors'] / data['total'] < 0.15 else 'UNHEALTHY'
        }
        for service, data in service_error_rates.items()
    }

    # Time-based analysis
    response_times_by_hour: dict[int, list[float]] = defaultdict(list)
    for log in logs:
        timestamp = log.get('@timestamp', '')
        rt = log.get('http', {}).get('response_time_ms')
        if timestamp and rt is not None:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                response_times_by_hour[dt.hour].append(rt)
            except ValueError:
                pass

    hourly_performance = {
        hour: calc_stats(times)
        for hour, times in sorted(response_times_by_hour.items())
    }

    # Peak load times
    requests_by_hour: Counter[int] = Counter()
    for log in logs:
        timestamp = log.get('@timestamp', '')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                requests_by_hour[dt.hour] += 1
            except ValueError:
                pass

    peak_hours = requests_by_hour.most_common(3)

    # Capacity recommendations
    recommendations: list[str] = []
    if slow_endpoints:
        recommendations.append(f"Optimize {len(slow_endpoints)} slow endpoints with avg response time > 1000ms")
    if disk_io_issues:
        recommendations.append(f"Investigate {len(disk_io_issues)} disk I/O latency issues")
    if connection_pool_issues:
        recommendations.append("Increase database connection pool size to prevent exhaustion")
    if response_time_spikes:
        recommendations.append(f"Investigate {len(response_time_spikes)} response time spikes (>10s)")

    unhealthy_services = [s for s, h in service_health.items() if h['health_status'] == 'UNHEALTHY']
    if unhealthy_services:
        recommendations.append(f"Address issues in unhealthy services: {', '.join(unhealthy_services)}")

    return {
        'summary': {
            'total_requests_analyzed': len(response_times),
            'overall_avg_response_time_ms': overall_stats['avg'],
            'overall_p95_response_time_ms': overall_stats['p95'],
            'overall_p99_response_time_ms': overall_stats['p99'],
            'slow_endpoint_count': len(slow_endpoints),
            'response_time_spike_count': len(response_time_spikes)
        },
        'response_times': {
            'overall': overall_stats,
            'by_endpoint': endpoint_stats,
            'by_service': service_stats,
            'slow_endpoints': slow_endpoints,
            'spikes': response_time_spikes[:20]
        },
        'resource_utilization': {
            'disk_io_issues': disk_io_issues,
            'memory_issues': memory_issues,
            'connection_pool_issues': connection_pool_issues
        },
        'database_performance': {
            'issues': database_issues,
            'total_issues': len(database_issues)
        },
        'service_health': service_health,
        'time_analysis': {
            'hourly_performance': hourly_performance,
            'peak_hours': [{'hour': h, 'requests': c} for h, c in peak_hours],
            'requests_by_hour': dict(sorted(requests_by_hour.items()))
        },
        'recommendations': recommendations
    }


def generate_html_report(title: str, content: dict[str, Any], report_type: str) -> str:
    """Generate an HTML report from analysis results.

    Args:
        title: Report title.
        content: Analysis results dictionary.
        report_type: Type of report (error, security, performance, summary).

    Returns:
        HTML string for the report.
    """
    css = """
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
        }
        h3 {
            color: #7f8c8d;
        }
        .summary-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .summary-box h2 {
            color: white;
            border-left-color: white;
        }
        .metric {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 10px 20px;
            border-radius: 5px;
            margin: 5px;
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
        }
        .metric-label {
            font-size: 12px;
            opacity: 0.9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .severity-critical {
            background-color: #e74c3c;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
        }
        .severity-high {
            background-color: #e67e22;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
        }
        .severity-medium {
            background-color: #f39c12;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
        }
        .severity-low {
            background-color: #27ae60;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
        }
        .status-healthy {
            color: #27ae60;
            font-weight: bold;
        }
        .status-degraded {
            color: #f39c12;
            font-weight: bold;
        }
        .status-unhealthy {
            color: #e74c3c;
            font-weight: bold;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin: 15px 0;
        }
        .recommendation {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 10px 15px;
            margin: 10px 0;
        }
        code {
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 12px;
        }
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 12px;
        }
    </style>
    """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    {css}
</head>
<body>
    <h1>{title}</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
"""

    if report_type == 'error':
        html += generate_error_html(content)
    elif report_type == 'security':
        html += generate_security_html(content)
    elif report_type == 'performance':
        html += generate_performance_html(content)
    elif report_type == 'summary':
        html += generate_summary_html(content)

    html += """
    <footer>
        <p>Elastic Logs Analysis Report - Generated by Comprehensive Log Analyzer</p>
    </footer>
</body>
</html>
"""
    return html


def generate_error_html(content: dict[str, Any]) -> str:
    """Generate HTML content for error analysis report."""
    summary = content['summary']

    html = f"""
    <div class="summary-box">
        <h2>Executive Summary</h2>
        <div class="metric">
            <div class="metric-value">{summary['total_logs']}</div>
            <div class="metric-label">Total Logs</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['total_errors']}</div>
            <div class="metric-label">Total Errors</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['error_rate_percent']}%</div>
            <div class="metric-label">Error Rate</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['unique_error_messages']}</div>
            <div class="metric-label">Unique Error Types</div>
        </div>
    </div>

    <div class="card">
        <h2>Error Distribution by HTTP Status Code</h2>
        <table>
            <tr><th>Status Code</th><th>Count</th><th>Description</th></tr>
"""
    status_descriptions = {
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        500: 'Internal Server Error',
        502: 'Bad Gateway',
        503: 'Service Unavailable',
        504: 'Gateway Timeout'
    }
    for code, count in content['status_code_distribution'].items():
        desc = status_descriptions.get(int(code), 'Unknown')
        html += f"            <tr><td>{code}</td><td>{count}</td><td>{desc}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Errors by Service</h2>
        <table>
            <tr><th>Service</th><th>Error Count</th></tr>
"""
    for service, count in content['errors_by_service'].items():
        html += f"            <tr><td>{service}</td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Error Messages Analysis</h2>
        <table>
            <tr><th>Error Message</th><th>Count</th></tr>
"""
    for message, count in content['error_message_types'].items():
        html += f"            <tr><td>{message}</td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Errors by Endpoint</h2>
        <table>
            <tr><th>Endpoint</th><th>Error Count</th></tr>
"""
    for endpoint, count in content['errors_by_endpoint'].items():
        html += f"            <tr><td><code>{endpoint}</code></td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Error Distribution by Hour</h2>
        <table>
            <tr><th>Hour (UTC)</th><th>Error Count</th></tr>
"""
    for hour, count in content['errors_by_hour'].items():
        html += f"            <tr><td>{hour}:00</td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Root Cause Analysis</h2>
"""
    for cause in content['root_causes']:
        html += f"""
        <div class="recommendation">
            <h3>{cause['error_message']}</h3>
            <p><strong>Occurrences:</strong> {cause['count']}</p>
            <p><strong>Potential Cause:</strong> {cause['potential_cause']}</p>
            <p><strong>Remediation:</strong> {cause['remediation']}</p>
        </div>
"""

    html += """    </div>

    <div class="card">
        <h2>Error Cascades</h2>
        <p>Errors occurring within 5 minutes across different services:</p>
        <table>
            <tr><th>First Error</th><th>First Service</th><th>Second Error</th><th>Second Service</th><th>Time Diff (s)</th></tr>
"""
    for cascade in content['error_cascades']:
        html += f"""            <tr>
                <td>{cascade['first_error']}</td>
                <td>{cascade['first_service']}</td>
                <td>{cascade['second_error']}</td>
                <td>{cascade['second_service']}</td>
                <td>{cascade['time_diff_seconds']}</td>
            </tr>\n"""

    html += """        </table>
    </div>
"""
    return html


def generate_security_html(content: dict[str, Any]) -> str:
    """Generate HTML content for security analysis report."""
    summary = content['summary']
    severity = content['severity_classification']

    html = f"""
    <div class="summary-box">
        <h2>Security Overview</h2>
        <div class="metric">
            <div class="metric-value">{summary['total_security_events']}</div>
            <div class="metric-label">Total Security Events</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['critical_count']}</div>
            <div class="metric-label">Critical</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['high_count']}</div>
            <div class="metric-label">High</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['medium_count']}</div>
            <div class="metric-label">Medium</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['low_count']}</div>
            <div class="metric-label">Low</div>
        </div>
    </div>

    <div class="card">
        <h2>Severity Classification</h2>
"""
    if severity['critical']:
        html += "        <h3><span class='severity-critical'>CRITICAL</span></h3><ul>\n"
        for finding in severity['critical']:
            html += f"            <li>{finding}</li>\n"
        html += "        </ul>\n"

    if severity['high']:
        html += "        <h3><span class='severity-high'>HIGH</span></h3><ul>\n"
        for finding in severity['high']:
            html += f"            <li>{finding}</li>\n"
        html += "        </ul>\n"

    if severity['medium']:
        html += "        <h3><span class='severity-medium'>MEDIUM</span></h3><ul>\n"
        for finding in severity['medium']:
            html += f"            <li>{finding}</li>\n"
        html += "        </ul>\n"

    if severity['low']:
        html += "        <h3><span class='severity-low'>LOW</span></h3><ul>\n"
        for finding in severity['low']:
            html += f"            <li>{finding}</li>\n"
        html += "        </ul>\n"

    html += """    </div>

    <div class="card">
        <h2>Authentication Analysis</h2>
"""
    auth = content['authentication']
    html += f"        <p><strong>Total Authentication Failures:</strong> {auth['total_failures']}</p>\n"

    if auth['brute_force_ips']:
        html += """        <h3>Potential Brute Force Attacks</h3>
        <table>
            <tr><th>IP Address</th><th>Failed Attempts</th></tr>
"""
        for ip, count in auth['brute_force_ips'].items():
            html += f"            <tr><td>{ip}</td><td>{count}</td></tr>\n"
        html += "        </table>\n"

    html += """        <h3>Failed Logins by IP</h3>
        <table>
            <tr><th>IP Address</th><th>Failed Attempts</th></tr>
"""
    for ip, count in auth['failures_by_ip'].items():
        html += f"            <tr><td>{ip}</td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Injection Attack Detection</h2>
        <h3>SQL Injection Attempts</h3>
"""
    sql_attacks = content['injection_attacks']['sql_injection']
    if sql_attacks:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Endpoint</th><th>Payload</th></tr>
"""
        for attack in sql_attacks:
            html += f"""            <tr>
                <td>{attack['log_id']}</td>
                <td>{attack['timestamp']}</td>
                <td>{attack['ip']}</td>
                <td><code>{attack['endpoint']}</code></td>
                <td><code>{attack['payload']}</code></td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No SQL injection attempts detected.</p>\n"

    html += "        <h3>XSS Attempts</h3>\n"
    xss_attacks = content['injection_attacks']['xss_attempts']
    if xss_attacks:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Endpoint</th><th>Payload</th></tr>
"""
        for attack in xss_attacks:
            html += f"""            <tr>
                <td>{attack['log_id']}</td>
                <td>{attack['timestamp']}</td>
                <td>{attack['ip']}</td>
                <td><code>{attack['endpoint']}</code></td>
                <td><code>{attack['payload']}</code></td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No XSS attempts detected.</p>\n"

    html += """    </div>

    <div class="card">
        <h2>Access Control Violations</h2>
"""
    access = content['access_control']
    html += f"        <p><strong>Total 403 Forbidden Responses:</strong> {access['total_403_responses']}</p>\n"

    if access['unauthorized_access_attempts']:
        html += """        <h3>Unauthorized Access Attempts</h3>
        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Target Resource</th></tr>
"""
        for attempt in access['unauthorized_access_attempts']:
            html += f"""            <tr>
                <td>{attempt['log_id']}</td>
                <td>{attempt['timestamp']}</td>
                <td>{attempt['ip']}</td>
                <td><code>{attempt['target_resource']}</code></td>
            </tr>\n"""
        html += "        </table>\n"

    html += """    </div>

    <div class="card">
        <h2>Rate Limiting Analysis</h2>
"""
    rate = content['rate_limiting']
    html += f"        <p><strong>Total Rate Limit Violations:</strong> {rate['total_violations']}</p>\n"

    if rate['violations']:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Requests/Min</th><th>Endpoint</th></tr>
"""
        for violation in rate['violations'][:20]:
            html += f"""            <tr>
                <td>{violation['log_id']}</td>
                <td>{violation['timestamp']}</td>
                <td>{violation['ip']}</td>
                <td>{violation['requests_per_minute']}</td>
                <td><code>{violation['endpoint']}</code></td>
            </tr>\n"""
        html += "        </table>\n"

    html += """    </div>

    <div class="card">
        <h2>Suspicious Activity</h2>
        <h3>Attack Tools Detected</h3>
"""
    tools = content['suspicious_activity']['attack_tools_detected']
    if tools:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Tool</th><th>User Agent</th></tr>
"""
        for tool in tools[:20]:
            html += f"""            <tr>
                <td>{tool['log_id']}</td>
                <td>{tool['timestamp']}</td>
                <td>{tool['ip']}</td>
                <td><span class="severity-high">{tool['tool_detected']}</span></td>
                <td><code>{tool['user_agent']}</code></td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No known attack tools detected.</p>\n"

    html += """        <h3>IPs with High Failure Rates</h3>
"""
    high_failure = content['suspicious_activity']['high_failure_ips']
    if high_failure:
        html += """        <table>
            <tr><th>IP Address</th><th>Total Requests</th><th>Failures</th><th>Failure Rate</th></tr>
"""
        for ip, data in high_failure.items():
            html += f"""            <tr>
                <td>{ip}</td>
                <td>{data['total']}</td>
                <td>{data['failures']}</td>
                <td>{data['rate']}%</td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No IPs with unusually high failure rates detected.</p>\n"

    html += """    </div>

    <div class="card">
        <h2>User Agent Analysis</h2>
        <table>
            <tr><th>User Agent</th><th>Request Count</th></tr>
"""
    for ua, count in content['user_agents']['distribution'].items():
        html += f"            <tr><td><code>{ua}</code></td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>
"""
    return html


def generate_performance_html(content: dict[str, Any]) -> str:
    """Generate HTML content for performance analysis report."""
    summary = content['summary']
    overall = content['response_times']['overall']

    html = f"""
    <div class="summary-box">
        <h2>Performance Overview</h2>
        <div class="metric">
            <div class="metric-value">{summary['total_requests_analyzed']}</div>
            <div class="metric-label">Requests Analyzed</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['overall_avg_response_time_ms']}ms</div>
            <div class="metric-label">Avg Response Time</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['overall_p95_response_time_ms']}ms</div>
            <div class="metric-label">P95 Response Time</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['overall_p99_response_time_ms']}ms</div>
            <div class="metric-label">P99 Response Time</div>
        </div>
        <div class="metric">
            <div class="metric-value">{summary['slow_endpoint_count']}</div>
            <div class="metric-label">Slow Endpoints</div>
        </div>
    </div>

    <div class="card">
        <h2>Overall Response Time Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value (ms)</th></tr>
            <tr><td>Minimum</td><td>{overall['min']}</td></tr>
            <tr><td>Maximum</td><td>{overall['max']}</td></tr>
            <tr><td>Average</td><td>{overall['avg']}</td></tr>
            <tr><td>Median</td><td>{overall['median']}</td></tr>
            <tr><td>P95</td><td>{overall['p95']}</td></tr>
            <tr><td>P99</td><td>{overall['p99']}</td></tr>
            <tr><td>Standard Deviation</td><td>{overall['std_dev']}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Response Times by Endpoint</h2>
        <table>
            <tr><th>Endpoint</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Max (ms)</th></tr>
"""
    for endpoint, stats in content['response_times']['by_endpoint'].items():
        html += f"""            <tr>
                <td><code>{endpoint}</code></td>
                <td>{stats['avg']}</td>
                <td>{stats['p95']}</td>
                <td>{stats['p99']}</td>
                <td>{stats['max']}</td>
            </tr>\n"""

    html += """        </table>
    </div>

    <div class="card">
        <h2>Response Times by Service</h2>
        <table>
            <tr><th>Service</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Max (ms)</th></tr>
"""
    for service, stats in content['response_times']['by_service'].items():
        html += f"""            <tr>
                <td>{service}</td>
                <td>{stats['avg']}</td>
                <td>{stats['p95']}</td>
                <td>{stats['p99']}</td>
                <td>{stats['max']}</td>
            </tr>\n"""

    html += """        </table>
    </div>

    <div class="card">
        <h2>Slow Endpoints (Avg > 1000ms)</h2>
"""
    slow = content['response_times']['slow_endpoints']
    if slow:
        html += """        <table>
            <tr><th>Endpoint</th><th>Avg (ms)</th><th>P95 (ms)</th><th>Max (ms)</th></tr>
"""
        for endpoint, stats in slow.items():
            html += f"""            <tr>
                <td><code>{endpoint}</code></td>
                <td>{stats['avg']}</td>
                <td>{stats['p95']}</td>
                <td>{stats['max']}</td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No endpoints with average response time > 1000ms.</p>\n"

    html += """    </div>

    <div class="card">
        <h2>Response Time Spikes (> 10s)</h2>
"""
    spikes = content['response_times']['spikes']
    if spikes:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Endpoint</th><th>Response Time (ms)</th></tr>
"""
        for spike in spikes:
            html += f"""            <tr>
                <td>{spike['log_id']}</td>
                <td>{spike['timestamp']}</td>
                <td>{spike['service']}</td>
                <td><code>{spike['endpoint']}</code></td>
                <td>{spike['response_time_ms']}</td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No response time spikes detected.</p>\n"

    html += """    </div>

    <div class="card">
        <h2>Resource Utilization Issues</h2>
        <h3>Disk I/O Issues</h3>
"""
    disk = content['resource_utilization']['disk_io_issues']
    if disk:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Read Latency (ms)</th><th>Write Latency (ms)</th><th>IOPS</th></tr>
"""
        for issue in disk[:20]:
            html += f"""            <tr>
                <td>{issue['log_id']}</td>
                <td>{issue['timestamp']}</td>
                <td>{issue['service']}</td>
                <td>{issue['read_latency_ms']}</td>
                <td>{issue['write_latency_ms']}</td>
                <td>{issue['iops']}</td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No disk I/O issues detected.</p>\n"

    html += "        <h3>Connection Pool Issues</h3>\n"
    pool = content['resource_utilization']['connection_pool_issues']
    if pool:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Message</th></tr>
"""
        for issue in pool:
            html += f"""            <tr>
                <td>{issue['log_id']}</td>
                <td>{issue['timestamp']}</td>
                <td>{issue['service']}</td>
                <td>{issue['message']}</td>
            </tr>\n"""
        html += "        </table>\n"
    else:
        html += "        <p>No connection pool issues detected.</p>\n"

    html += """    </div>

    <div class="card">
        <h2>Database Performance Issues</h2>
"""
    db = content['database_performance']
    html += f"        <p><strong>Total Database Issues:</strong> {db['total_issues']}</p>\n"
    if db['issues']:
        html += """        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Message</th></tr>
"""
        for issue in db['issues']:
            html += f"""            <tr>
                <td>{issue['log_id']}</td>
                <td>{issue['timestamp']}</td>
                <td>{issue['service']}</td>
                <td>{issue['message']}</td>
            </tr>\n"""
        html += "        </table>\n"

    html += """    </div>

    <div class="card">
        <h2>Service Health Status</h2>
        <table>
            <tr><th>Service</th><th>Total Requests</th><th>Errors</th><th>Error Rate</th><th>Status</th></tr>
"""
    for service, health in content['service_health'].items():
        status_class = f"status-{health['health_status'].lower()}"
        html += f"""            <tr>
                <td>{service}</td>
                <td>{health['total_requests']}</td>
                <td>{health['errors']}</td>
                <td>{health['error_rate']}%</td>
                <td><span class="{status_class}">{health['health_status']}</span></td>
            </tr>\n"""

    html += """        </table>
    </div>

    <div class="card">
        <h2>Hourly Performance Analysis</h2>
        <table>
            <tr><th>Hour (UTC)</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th></tr>
"""
    for hour, stats in content['time_analysis']['hourly_performance'].items():
        html += f"""            <tr>
                <td>{hour}:00</td>
                <td>{stats['avg']}</td>
                <td>{stats['p95']}</td>
                <td>{stats['p99']}</td>
            </tr>\n"""

    html += """        </table>
    </div>

    <div class="card">
        <h2>Peak Load Times</h2>
        <table>
            <tr><th>Hour (UTC)</th><th>Request Count</th></tr>
"""
    for peak in content['time_analysis']['peak_hours']:
        html += f"            <tr><td>{peak['hour']}:00</td><td>{peak['requests']}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="card">
        <h2>Recommendations</h2>
"""
    for rec in content['recommendations']:
        html += f"        <div class='recommendation'>{rec}</div>\n"

    html += """    </div>
"""
    return html


def generate_summary_html(content: dict[str, Any]) -> str:
    """Generate HTML content for summary report."""
    error = content['error_analysis']['summary']
    security = content['security_analysis']['summary']
    performance = content['performance_analysis']['summary']

    html = f"""
    <div class="summary-box">
        <h2>Analysis Summary</h2>
        <p>Comprehensive analysis of Elastic logs covering error patterns, security issues, and performance anomalies.</p>
    </div>

    <div class="card">
        <h2>Error Analysis Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Logs Analyzed</td><td>{error['total_logs']}</td></tr>
            <tr><td>Total Errors</td><td>{error['total_errors']}</td></tr>
            <tr><td>Error Rate</td><td>{error['error_rate_percent']}%</td></tr>
            <tr><td>Unique Error Types</td><td>{error['unique_error_messages']}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Security Analysis Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Security Events</td><td>{security['total_security_events']}</td></tr>
            <tr><td>Critical Findings</td><td><span class="severity-critical">{security['critical_count']}</span></td></tr>
            <tr><td>High Findings</td><td><span class="severity-high">{security['high_count']}</span></td></tr>
            <tr><td>Medium Findings</td><td><span class="severity-medium">{security['medium_count']}</span></td></tr>
            <tr><td>Low Findings</td><td><span class="severity-low">{security['low_count']}</span></td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Performance Analysis Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Requests Analyzed</td><td>{performance['total_requests_analyzed']}</td></tr>
            <tr><td>Average Response Time</td><td>{performance['overall_avg_response_time_ms']}ms</td></tr>
            <tr><td>P95 Response Time</td><td>{performance['overall_p95_response_time_ms']}ms</td></tr>
            <tr><td>P99 Response Time</td><td>{performance['overall_p99_response_time_ms']}ms</td></tr>
            <tr><td>Slow Endpoints</td><td>{performance['slow_endpoint_count']}</td></tr>
            <tr><td>Response Time Spikes</td><td>{performance['response_time_spike_count']}</td></tr>
        </table>
    </div>

    <div class="card">
        <h2>Key Findings</h2>
"""
    # Add key findings from each analysis
    severity = content['security_analysis']['severity_classification']
    if severity['critical']:
        html += "        <h3>Critical Security Issues</h3><ul>\n"
        for finding in severity['critical']:
            html += f"            <li><span class='severity-critical'>CRITICAL</span> {finding}</li>\n"
        html += "        </ul>\n"

    if severity['high']:
        html += "        <h3>High Priority Issues</h3><ul>\n"
        for finding in severity['high']:
            html += f"            <li><span class='severity-high'>HIGH</span> {finding}</li>\n"
        html += "        </ul>\n"

    # Add performance recommendations
    recommendations = content['performance_analysis']['recommendations']
    if recommendations:
        html += "        <h3>Performance Recommendations</h3><ul>\n"
        for rec in recommendations:
            html += f"            <li>{rec}</li>\n"
        html += "        </ul>\n"

    # Add error root causes
    root_causes = content['error_analysis']['root_causes']
    if root_causes:
        html += "        <h3>Error Root Causes</h3><ul>\n"
        for cause in root_causes[:5]:
            html += f"            <li><strong>{cause['error_message']}</strong> ({cause['count']} occurrences): {cause['potential_cause']}</li>\n"
        html += "        </ul>\n"

    html += """    </div>

    <div class="card">
        <h2>Recommended Actions</h2>
        <ol>
"""
    # Generate prioritized action items
    actions = []
    if severity['critical']:
        actions.append("Immediately investigate and remediate critical security findings (SQL injection, XSS attempts)")
    if severity['high']:
        actions.append("Address high-priority security issues including brute force attacks and attack tool usage")
    if performance['slow_endpoint_count'] > 0:
        actions.append(f"Optimize {performance['slow_endpoint_count']} slow endpoints with response times > 1000ms")
    if performance['response_time_spike_count'] > 0:
        actions.append(f"Investigate {performance['response_time_spike_count']} response time spikes exceeding 10 seconds")
    if error['error_rate_percent'] > 5:
        actions.append(f"Reduce error rate from {error['error_rate_percent']}% to below 5%")

    for action in actions:
        html += f"            <li>{action}</li>\n"

    html += """        </ol>
    </div>
"""
    return html


def main() -> None:
    """Main function to run the comprehensive log analysis."""
    import argparse

    parser = argparse.ArgumentParser(description='Comprehensive Elastic Logs Analysis')
    parser.add_argument('--log-file', required=True, help='Path to the JSON log file')
    parser.add_argument('--output-dir', default='analysis', help='Directory to save reports')
    args = parser.parse_args()

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Loading logs from {args.log_file}...")
    logs = load_logs(args.log_file)
    print(f"Loaded {len(logs)} log entries")

    print("\nPerforming Error Pattern Analysis...")
    error_results = analyze_errors(logs)
    print(f"  - Found {error_results['summary']['total_errors']} errors")
    print(f"  - Error rate: {error_results['summary']['error_rate_percent']}%")

    print("\nPerforming Security Issue Detection...")
    security_results = analyze_security(logs)
    print(f"  - Found {security_results['summary']['total_security_events']} security events")
    print(f"  - Critical: {security_results['summary']['critical_count']}")
    print(f"  - High: {security_results['summary']['high_count']}")

    print("\nPerforming Performance Anomaly Analysis...")
    performance_results = analyze_performance(logs)
    print(f"  - Avg response time: {performance_results['summary']['overall_avg_response_time_ms']}ms")
    print(f"  - P95 response time: {performance_results['summary']['overall_p95_response_time_ms']}ms")
    print(f"  - Slow endpoints: {performance_results['summary']['slow_endpoint_count']}")

    # Generate HTML reports
    print("\nGenerating HTML reports...")

    error_html = generate_html_report(
        "Error Pattern Analysis Report",
        error_results,
        'error'
    )
    error_path = os.path.join(args.output_dir, 'error_analysis_report.html')
    with open(error_path, 'w', encoding='utf-8') as f:
        f.write(error_html)
    print(f"  - Saved: {error_path}")

    security_html = generate_html_report(
        "Security Issue Detection Report",
        security_results,
        'security'
    )
    security_path = os.path.join(args.output_dir, 'security_analysis_report.html')
    with open(security_path, 'w', encoding='utf-8') as f:
        f.write(security_html)
    print(f"  - Saved: {security_path}")

    performance_html = generate_html_report(
        "Performance Anomaly Analysis Report",
        performance_results,
        'performance'
    )
    performance_path = os.path.join(args.output_dir, 'performance_analysis_report.html')
    with open(performance_path, 'w', encoding='utf-8') as f:
        f.write(performance_html)
    print(f"  - Saved: {performance_path}")

    # Generate summary report
    summary_content = {
        'error_analysis': error_results,
        'security_analysis': security_results,
        'performance_analysis': performance_results
    }
    summary_html = generate_html_report(
        "Elastic Logs Analysis Summary",
        summary_content,
        'summary'
    )
    summary_path = os.path.join(args.output_dir, 'analysis_summary.html')
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(summary_html)
    print(f"  - Saved: {summary_path}")

    print("\nAnalysis complete!")


if __name__ == '__main__':
    main()
