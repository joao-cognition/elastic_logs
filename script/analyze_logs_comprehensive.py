#!/usr/bin/env python3
"""Comprehensive Elastic Logs Analysis Script.

This script performs three types of analysis on Elastic logs:
1. Error Pattern Analysis
2. Security Issue Detection
3. Performance Anomaly Analysis

It generates HTML reports for each analysis type and a summary report.
"""

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load logs from a JSON file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entries as dictionaries.
    """
    with open(log_file, "r") as f:
        return json.load(f)


def analyze_errors(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform error pattern analysis on logs.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing error analysis results.
    """
    error_logs = [log for log in logs if log.get("level") == "ERROR"]
    all_logs = logs

    errors_by_status = Counter()
    errors_by_service = Counter()
    errors_by_message = Counter()
    errors_by_hour = defaultdict(list)
    endpoint_errors = Counter()
    error_details = []

    for log in error_logs:
        status_code = log.get("http", {}).get("status_code", "unknown")
        service = log.get("service", "unknown")
        message = log.get("message", "unknown")
        endpoint = log.get("http", {}).get("endpoint", "unknown")
        timestamp = log.get("@timestamp", "")

        errors_by_status[status_code] += 1
        errors_by_service[service] += 1
        errors_by_message[message] += 1
        endpoint_errors[endpoint] += 1

        if timestamp:
            hour = timestamp[11:13]
            errors_by_hour[hour].append(log)

        error_details.append({
            "log_id": log.get("log_id"),
            "timestamp": timestamp,
            "service": service,
            "status_code": status_code,
            "message": message,
            "endpoint": endpoint,
            "error_type": log.get("error", {}).get("type", "N/A"),
            "stack_trace": log.get("error", {}).get("stack_trace", "N/A"),
            "correlation_id": log.get("error", {}).get("correlation_id", "N/A"),
        })

    total_requests = len(all_logs)
    error_rate = (len(error_logs) / total_requests * 100) if total_requests > 0 else 0

    endpoint_error_rates = {}
    endpoint_totals = Counter(log.get("http", {}).get("endpoint", "unknown") for log in all_logs)
    for endpoint, error_count in endpoint_errors.items():
        total = endpoint_totals.get(endpoint, 1)
        endpoint_error_rates[endpoint] = {
            "errors": error_count,
            "total": total,
            "rate": round(error_count / total * 100, 2)
        }

    error_cascades = []
    sorted_errors = sorted(error_details, key=lambda x: x["timestamp"])
    for i in range(len(sorted_errors) - 1):
        current = sorted_errors[i]
        next_error = sorted_errors[i + 1]
        if current["service"] != next_error["service"]:
            error_cascades.append({
                "trigger": current,
                "subsequent": next_error
            })

    return {
        "total_errors": len(error_logs),
        "total_requests": total_requests,
        "error_rate": round(error_rate, 2),
        "errors_by_status": dict(errors_by_status.most_common()),
        "errors_by_service": dict(errors_by_service.most_common()),
        "errors_by_message": dict(errors_by_message.most_common()),
        "errors_by_hour": {k: len(v) for k, v in sorted(errors_by_hour.items())},
        "endpoint_error_rates": endpoint_error_rates,
        "error_cascades": error_cascades[:5],
        "error_details": error_details,
    }


def analyze_security(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform security issue detection on logs.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing security analysis results.
    """
    security_events = []
    failed_auth = []
    suspicious_ips = defaultdict(list)
    injection_attempts = []
    access_violations = []
    rate_limit_violations = []
    suspicious_user_agents = []

    attack_tools = ["sqlmap", "nikto", "nmap", "burp", "hydra", "metasploit"]
    sql_injection_patterns = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "--", "/*"]
    xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]

    ip_request_counts = Counter()
    ip_failure_counts = Counter()

    for log in logs:
        client_ip = log.get("client", {}).get("ip", "unknown")
        user_agent = log.get("client", {}).get("user_agent", "")
        status_code = log.get("http", {}).get("status_code", 0)
        security_info = log.get("security", {})
        message = log.get("message", "")

        ip_request_counts[client_ip] += 1
        if status_code in [401, 403, 429]:
            ip_failure_counts[client_ip] += 1

        if status_code == 401:
            failed_auth.append({
                "log_id": log.get("log_id"),
                "timestamp": log.get("@timestamp"),
                "ip": client_ip,
                "user_agent": user_agent,
                "endpoint": log.get("http", {}).get("endpoint"),
                "message": message,
            })

        if security_info:
            event_type = security_info.get("event_type", "")
            security_events.append({
                "log_id": log.get("log_id"),
                "timestamp": log.get("@timestamp"),
                "ip": client_ip,
                "event_type": event_type,
                "details": security_info,
            })

            if event_type == "SQL_INJECTION_ATTEMPT":
                injection_attempts.append({
                    "log_id": log.get("log_id"),
                    "timestamp": log.get("@timestamp"),
                    "ip": client_ip,
                    "payload": security_info.get("payload", ""),
                    "endpoint": log.get("http", {}).get("endpoint"),
                })

            if event_type == "UNAUTHORIZED_ACCESS":
                access_violations.append({
                    "log_id": log.get("log_id"),
                    "timestamp": log.get("@timestamp"),
                    "ip": client_ip,
                    "target": security_info.get("target_resource", ""),
                    "endpoint": log.get("http", {}).get("endpoint"),
                })

            if event_type == "RATE_LIMIT_EXCEEDED":
                rate_limit_violations.append({
                    "log_id": log.get("log_id"),
                    "timestamp": log.get("@timestamp"),
                    "ip": client_ip,
                    "requests_per_minute": security_info.get("requests_per_minute", 0),
                })

        for tool in attack_tools:
            if tool.lower() in user_agent.lower():
                suspicious_user_agents.append({
                    "log_id": log.get("log_id"),
                    "timestamp": log.get("@timestamp"),
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "detected_tool": tool,
                })
                suspicious_ips[client_ip].append({
                    "reason": f"Attack tool detected: {tool}",
                    "log_id": log.get("log_id"),
                })
                break

        if "SQL injection" in message.lower() or "injection" in message.lower():
            suspicious_ips[client_ip].append({
                "reason": "SQL injection pattern in message",
                "log_id": log.get("log_id"),
            })

    high_failure_ips = []
    for ip, failure_count in ip_failure_counts.items():
        total = ip_request_counts[ip]
        failure_rate = failure_count / total * 100 if total > 0 else 0
        if failure_rate > 30 or failure_count >= 3:
            high_failure_ips.append({
                "ip": ip,
                "failures": failure_count,
                "total_requests": total,
                "failure_rate": round(failure_rate, 2),
            })

    brute_force_candidates = []
    for ip, count in ip_failure_counts.items():
        if count >= 3:
            brute_force_candidates.append({
                "ip": ip,
                "failed_attempts": count,
                "severity": "HIGH" if count >= 5 else "MEDIUM",
            })

    findings = []
    for attempt in injection_attempts:
        findings.append({
            "severity": "CRITICAL",
            "type": "SQL Injection Attempt",
            "details": attempt,
        })
    for violation in access_violations:
        findings.append({
            "severity": "HIGH",
            "type": "Unauthorized Access Attempt",
            "details": violation,
        })
    for candidate in brute_force_candidates:
        findings.append({
            "severity": candidate["severity"],
            "type": "Potential Brute Force Attack",
            "details": candidate,
        })
    for ua in suspicious_user_agents:
        findings.append({
            "severity": "HIGH",
            "type": "Attack Tool Detected",
            "details": ua,
        })

    findings.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
        x["severity"], 4
    ))

    return {
        "total_security_events": len(security_events),
        "failed_auth_attempts": len(failed_auth),
        "failed_auth_details": failed_auth,
        "injection_attempts": injection_attempts,
        "access_violations": access_violations,
        "rate_limit_violations": rate_limit_violations,
        "suspicious_user_agents": suspicious_user_agents,
        "high_failure_ips": high_failure_ips,
        "brute_force_candidates": brute_force_candidates,
        "suspicious_ips": {k: v for k, v in suspicious_ips.items()},
        "prioritized_findings": findings,
        "severity_summary": {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
            "medium": len([f for f in findings if f["severity"] == "MEDIUM"]),
            "low": len([f for f in findings if f["severity"] == "LOW"]),
        },
    }


def analyze_performance(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform performance anomaly analysis on logs.

    Args:
        logs: List of log entries.

    Returns:
        Dictionary containing performance analysis results.
    """
    response_times = []
    endpoint_response_times = defaultdict(list)
    service_response_times = defaultdict(list)
    slow_requests = []
    memory_issues = []
    connection_issues = []
    performance_by_hour = defaultdict(list)

    slow_threshold_ms = 1000

    for log in logs:
        http_info = log.get("http", {})
        response_time = http_info.get("response_time_ms", 0)
        endpoint = http_info.get("endpoint", "unknown")
        service = log.get("service", "unknown")
        timestamp = log.get("@timestamp", "")
        message = log.get("message", "")
        performance_info = log.get("performance", {})

        if response_time:
            response_times.append(response_time)
            endpoint_response_times[endpoint].append(response_time)
            service_response_times[service].append(response_time)

            if timestamp:
                hour = timestamp[11:13]
                performance_by_hour[hour].append(response_time)

            if response_time > slow_threshold_ms:
                slow_requests.append({
                    "log_id": log.get("log_id"),
                    "timestamp": timestamp,
                    "service": service,
                    "endpoint": endpoint,
                    "response_time_ms": response_time,
                    "status_code": http_info.get("status_code"),
                })

        if "memory" in message.lower() or "out of memory" in message.lower():
            memory_issues.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "service": service,
                "message": message,
                "performance_data": performance_info,
            })

        if "connection" in message.lower() or "pool exhausted" in message.lower():
            connection_issues.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "service": service,
                "message": message,
            })

        if performance_info:
            read_latency = performance_info.get("read_latency_ms", 0)
            write_latency = performance_info.get("write_latency_ms", 0)
            if read_latency > 200 or write_latency > 200:
                if not any(m["log_id"] == log.get("log_id") for m in memory_issues):
                    memory_issues.append({
                        "log_id": log.get("log_id"),
                        "timestamp": timestamp,
                        "service": service,
                        "message": message,
                        "performance_data": performance_info,
                    })

    def calc_stats(times: list[int]) -> dict[str, float]:
        if not times:
            return {"min": 0, "max": 0, "avg": 0, "median": 0, "p95": 0, "p99": 0}
        sorted_times = sorted(times)
        n = len(sorted_times)
        return {
            "min": min(times),
            "max": max(times),
            "avg": round(statistics.mean(times), 2),
            "median": round(statistics.median(times), 2),
            "p95": sorted_times[int(n * 0.95)] if n > 0 else 0,
            "p99": sorted_times[int(n * 0.99)] if n > 0 else 0,
        }

    overall_stats = calc_stats(response_times)

    endpoint_stats = {}
    for endpoint, times in endpoint_response_times.items():
        stats = calc_stats(times)
        endpoint_stats[endpoint] = {
            "request_count": len(times),
            **stats,
            "slow_requests": len([t for t in times if t > slow_threshold_ms]),
        }

    service_stats = {}
    for service, times in service_response_times.items():
        stats = calc_stats(times)
        service_stats[service] = {
            "request_count": len(times),
            **stats,
            "slow_requests": len([t for t in times if t > slow_threshold_ms]),
        }

    hourly_stats = {}
    for hour, times in sorted(performance_by_hour.items()):
        hourly_stats[hour] = {
            "request_count": len(times),
            "avg_response_time": round(statistics.mean(times), 2) if times else 0,
            "max_response_time": max(times) if times else 0,
        }

    peak_hours = sorted(
        hourly_stats.items(),
        key=lambda x: x[1]["request_count"],
        reverse=True
    )[:3]

    slowest_endpoints = sorted(
        endpoint_stats.items(),
        key=lambda x: x[1]["avg"],
        reverse=True
    )[:5]

    anomalies = []
    if overall_stats["p99"] > 5000:
        anomalies.append({
            "type": "High P99 Latency",
            "severity": "HIGH",
            "details": f"P99 response time is {overall_stats['p99']}ms (threshold: 5000ms)",
        })
    if len(memory_issues) > 0:
        anomalies.append({
            "type": "Memory Issues Detected",
            "severity": "HIGH",
            "details": f"{len(memory_issues)} memory-related issues found",
        })
    if len(connection_issues) > 0:
        anomalies.append({
            "type": "Connection Pool Issues",
            "severity": "CRITICAL",
            "details": f"{len(connection_issues)} connection pool issues found",
        })

    return {
        "total_requests": len(logs),
        "overall_stats": overall_stats,
        "endpoint_stats": endpoint_stats,
        "service_stats": service_stats,
        "hourly_stats": hourly_stats,
        "slow_requests": slow_requests,
        "slow_request_count": len(slow_requests),
        "memory_issues": memory_issues,
        "connection_issues": connection_issues,
        "peak_hours": [{"hour": h, **s} for h, s in peak_hours],
        "slowest_endpoints": [{"endpoint": e, **s} for e, s in slowest_endpoints],
        "anomalies": anomalies,
    }


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
    <title>Error Pattern Analysis Report</title>
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
        }}
        h3 {{
            color: #388e3c;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 8px;
            min-width: 150px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #1976d2;
        }}
        .metric-label {{
            font-size: 0.9em;
            color: #666;
        }}
        .error-metric {{
            background: #ffebee;
        }}
        .error-metric .metric-value {{
            color: #d32f2f;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #1976d2;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .status-500 {{ color: #d32f2f; font-weight: bold; }}
        .status-502 {{ color: #f57c00; font-weight: bold; }}
        .status-503 {{ color: #7b1fa2; font-weight: bold; }}
        .status-504 {{ color: #c62828; font-weight: bold; }}
        .recommendation {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 10px 0;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        .code {{
            font-family: monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <h1>Error Pattern Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

    <div class="summary-card">
        <h2>Executive Summary</h2>
        <div class="metric error-metric">
            <div class="metric-value">{analysis['total_errors']}</div>
            <div class="metric-label">Total Errors</div>
        </div>
        <div class="metric">
            <div class="metric-value">{analysis['total_requests']}</div>
            <div class="metric-label">Total Requests</div>
        </div>
        <div class="metric error-metric">
            <div class="metric-value">{analysis['error_rate']}%</div>
            <div class="metric-label">Error Rate</div>
        </div>
    </div>

    <div class="summary-card">
        <h2>1.1 Error Frequency Analysis</h2>

        <h3>Errors by HTTP Status Code</h3>
        <table>
            <tr><th>Status Code</th><th>Count</th><th>Description</th></tr>
"""
    status_descriptions = {
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
    }
    for status, count in analysis['errors_by_status'].items():
        status_class = f"status-{status}"
        desc = status_descriptions.get(status, "Unknown")
        html += f'            <tr><td class="{status_class}">{status}</td><td>{count}</td><td>{desc}</td></tr>\n'

    html += """        </table>

        <h3>Errors by Service</h3>
        <table>
            <tr><th>Service</th><th>Error Count</th></tr>
"""
    for service, count in analysis['errors_by_service'].items():
        html += f"            <tr><td>{service}</td><td>{count}</td></tr>\n"

    html += """        </table>

        <h3>Errors by Message Type</h3>
        <table>
            <tr><th>Error Message</th><th>Count</th></tr>
"""
    for message, count in analysis['errors_by_message'].items():
        html += f"            <tr><td>{message}</td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="summary-card">
        <h2>1.2 Error Pattern Detection</h2>

        <h3>Endpoint Error Rates</h3>
        <table>
            <tr><th>Endpoint</th><th>Errors</th><th>Total Requests</th><th>Error Rate</th></tr>
"""
    sorted_endpoints = sorted(
        analysis['endpoint_error_rates'].items(),
        key=lambda x: x[1]['rate'],
        reverse=True
    )
    for endpoint, data in sorted_endpoints:
        if data['errors'] > 0:
            html += f"            <tr><td>{endpoint}</td><td>{data['errors']}</td><td>{data['total']}</td><td>{data['rate']}%</td></tr>\n"

    html += """        </table>

        <h3>Error Cascades (Potential Chain Reactions)</h3>
"""
    if analysis['error_cascades']:
        html += "        <table>\n            <tr><th>Trigger Service</th><th>Trigger Error</th><th>Subsequent Service</th><th>Subsequent Error</th></tr>\n"
        for cascade in analysis['error_cascades']:
            html += f"            <tr><td>{cascade['trigger']['service']}</td><td>{cascade['trigger']['message']}</td><td>{cascade['subsequent']['service']}</td><td>{cascade['subsequent']['message']}</td></tr>\n"
        html += "        </table>\n"
    else:
        html += "        <p>No error cascades detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>1.3 Root Cause Analysis</h2>
"""
    root_causes = {
        "Internal server error: out of memory exception": {
            "cause": "Memory exhaustion in application services",
            "remediation": "Increase memory limits, implement memory profiling, add circuit breakers"
        },
        "Connection refused: service unreachable": {
            "cause": "Service unavailability or network issues",
            "remediation": "Check service health, verify network connectivity, implement retry logic"
        },
        "Internal server error: database connection pool exhausted": {
            "cause": "Database connection pool saturation",
            "remediation": "Increase pool size, optimize query performance, implement connection timeouts"
        },
        "Request timeout: upstream service unavailable": {
            "cause": "Upstream service latency or unavailability",
            "remediation": "Implement circuit breakers, increase timeout values, add fallback mechanisms"
        },
    }

    for message in analysis['errors_by_message'].keys():
        if message in root_causes:
            rc = root_causes[message]
            html += f"""        <h3>{message}</h3>
        <p><strong>Potential Root Cause:</strong> {rc['cause']}</p>
        <div class="recommendation">
            <strong>Recommended Remediation:</strong> {rc['remediation']}
        </div>
"""

    html += """    </div>

    <div class="summary-card">
        <h2>1.4 Time-based Analysis</h2>

        <h3>Error Distribution by Hour</h3>
        <table>
            <tr><th>Hour (UTC)</th><th>Error Count</th></tr>
"""
    for hour, count in analysis['errors_by_hour'].items():
        html += f"            <tr><td>{hour}:00</td><td>{count}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="summary-card">
        <h2>1.5 Impact Assessment</h2>

        <h3>Most Affected Services</h3>
        <table>
            <tr><th>Service</th><th>Error Count</th><th>Impact Level</th></tr>
"""
    for service, count in analysis['errors_by_service'].items():
        impact = "HIGH" if count >= 3 else "MEDIUM" if count >= 2 else "LOW"
        html += f"            <tr><td>{service}</td><td>{count}</td><td>{impact}</td></tr>\n"

    html += """        </table>

        <h3>Detailed Error Log</h3>
        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Status</th><th>Message</th></tr>
"""
    for error in analysis['error_details'][:20]:
        html += f"            <tr><td class='code'>{error['log_id']}</td><td class='timestamp'>{error['timestamp']}</td><td>{error['service']}</td><td class='status-{error['status_code']}'>{error['status_code']}</td><td>{error['message']}</td></tr>\n"

    html += """        </table>
    </div>
</body>
</html>
"""
    with open(output_path, "w") as f:
        f.write(html)


def generate_security_html_report(analysis: dict[str, Any], output_path: str) -> None:
    """Generate HTML report for security analysis.

    Args:
        analysis: Security analysis results.
        output_path: Path to save the HTML report.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Issue Detection Report</title>
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
            color: #7b1fa2;
            border-bottom: 3px solid #7b1fa2;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #1976d2;
            margin-top: 30px;
        }}
        h3 {{
            color: #388e3c;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 8px;
            min-width: 150px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #1976d2;
        }}
        .metric-label {{
            font-size: 0.9em;
            color: #666;
        }}
        .critical {{
            background: #ffebee;
            border-left: 4px solid #d32f2f;
        }}
        .critical .metric-value {{ color: #d32f2f; }}
        .high {{
            background: #fff3e0;
            border-left: 4px solid #f57c00;
        }}
        .high .metric-value {{ color: #f57c00; }}
        .medium {{
            background: #fff8e1;
            border-left: 4px solid #ffc107;
        }}
        .medium .metric-value {{ color: #f9a825; }}
        .low {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
        }}
        .low .metric-value {{ color: #388e3c; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #7b1fa2;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-critical {{ background: #ffebee; color: #d32f2f; font-weight: bold; }}
        .severity-high {{ background: #fff3e0; color: #f57c00; font-weight: bold; }}
        .severity-medium {{ background: #fff8e1; color: #f9a825; font-weight: bold; }}
        .severity-low {{ background: #e8f5e9; color: #388e3c; font-weight: bold; }}
        .alert {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .alert-critical {{
            background: #ffebee;
            border-left: 4px solid #d32f2f;
        }}
        .alert-high {{
            background: #fff3e0;
            border-left: 4px solid #f57c00;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        .code {{
            font-family: monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        .ip-address {{
            font-family: monospace;
            color: #d32f2f;
        }}
    </style>
</head>
<body>
    <h1>Security Issue Detection Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

    <div class="summary-card">
        <h2>2.7 Severity Classification Summary</h2>
        <div class="metric critical">
            <div class="metric-value">{analysis['severity_summary']['critical']}</div>
            <div class="metric-label">Critical</div>
        </div>
        <div class="metric high">
            <div class="metric-value">{analysis['severity_summary']['high']}</div>
            <div class="metric-label">High</div>
        </div>
        <div class="metric medium">
            <div class="metric-value">{analysis['severity_summary']['medium']}</div>
            <div class="metric-label">Medium</div>
        </div>
        <div class="metric low">
            <div class="metric-value">{analysis['severity_summary']['low']}</div>
            <div class="metric-label">Low</div>
        </div>
    </div>

    <div class="summary-card">
        <h2>Prioritized Security Findings</h2>
        <table>
            <tr><th>Severity</th><th>Type</th><th>Details</th></tr>
"""
    for finding in analysis['prioritized_findings'][:15]:
        severity_class = f"severity-{finding['severity'].lower()}"
        details_str = str(finding['details'])[:100] + "..." if len(str(finding['details'])) > 100 else str(finding['details'])
        html += f"            <tr><td class='{severity_class}'>{finding['severity']}</td><td>{finding['type']}</td><td>{details_str}</td></tr>\n"

    html += f"""        </table>
    </div>

    <div class="summary-card">
        <h2>2.1 Authentication Analysis</h2>

        <h3>Failed Login Attempts: {analysis['failed_auth_attempts']}</h3>
        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>User Agent</th></tr>
"""
    for auth in analysis['failed_auth_details'][:10]:
        html += f"            <tr><td class='code'>{auth['log_id']}</td><td class='timestamp'>{auth['timestamp']}</td><td class='ip-address'>{auth['ip']}</td><td>{auth['endpoint']}</td><td>{auth['user_agent'][:50]}...</td></tr>\n"

    html += """        </table>

        <h3>Brute Force Attack Candidates</h3>
"""
    if analysis['brute_force_candidates']:
        html += "        <table>\n            <tr><th>IP Address</th><th>Failed Attempts</th><th>Severity</th></tr>\n"
        for candidate in analysis['brute_force_candidates']:
            severity_class = f"severity-{candidate['severity'].lower()}"
            html += f"            <tr><td class='ip-address'>{candidate['ip']}</td><td>{candidate['failed_attempts']}</td><td class='{severity_class}'>{candidate['severity']}</td></tr>\n"
        html += "        </table>\n"
    else:
        html += "        <p>No brute force attack patterns detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>2.2 Suspicious IP Detection</h2>

        <h3>High Failure Rate IPs</h3>
        <table>
            <tr><th>IP Address</th><th>Failures</th><th>Total Requests</th><th>Failure Rate</th></tr>
"""
    for ip_data in analysis['high_failure_ips']:
        html += f"            <tr><td class='ip-address'>{ip_data['ip']}</td><td>{ip_data['failures']}</td><td>{ip_data['total_requests']}</td><td>{ip_data['failure_rate']}%</td></tr>\n"

    html += """        </table>

        <h3>IPs with Suspicious Activity</h3>
        <table>
            <tr><th>IP Address</th><th>Suspicious Activities</th></tr>
"""
    for ip, activities in analysis['suspicious_ips'].items():
        reasons = ", ".join([a['reason'] for a in activities[:3]])
        html += f"            <tr><td class='ip-address'>{ip}</td><td>{reasons}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="summary-card">
        <h2>2.3 Injection Attack Detection</h2>

        <h3>SQL Injection Attempts</h3>
"""
    if analysis['injection_attempts']:
        html += "        <table>\n            <tr><th>Log ID</th><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Payload</th></tr>\n"
        for attempt in analysis['injection_attempts']:
            html += f"            <tr><td class='code'>{attempt['log_id']}</td><td class='timestamp'>{attempt['timestamp']}</td><td class='ip-address'>{attempt['ip']}</td><td>{attempt['endpoint']}</td><td class='code'>{attempt['payload']}</td></tr>\n"
        html += "        </table>\n"
        html += """        <div class="alert alert-critical">
            <strong>CRITICAL:</strong> SQL injection attempts detected. Immediate review and remediation required.
        </div>
"""
    else:
        html += "        <p>No SQL injection attempts detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>2.4 Access Control Violations</h2>

        <h3>Unauthorized Access Attempts</h3>
"""
    if analysis['access_violations']:
        html += "        <table>\n            <tr><th>Log ID</th><th>Timestamp</th><th>IP Address</th><th>Target Resource</th></tr>\n"
        for violation in analysis['access_violations']:
            html += f"            <tr><td class='code'>{violation['log_id']}</td><td class='timestamp'>{violation['timestamp']}</td><td class='ip-address'>{violation['ip']}</td><td>{violation['target']}</td></tr>\n"
        html += "        </table>\n"
    else:
        html += "        <p>No unauthorized access attempts detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>2.5 Rate Limiting Analysis</h2>

        <h3>Rate Limit Violations</h3>
"""
    if analysis['rate_limit_violations']:
        html += "        <table>\n            <tr><th>Log ID</th><th>Timestamp</th><th>IP Address</th><th>Requests/Minute</th></tr>\n"
        for violation in analysis['rate_limit_violations']:
            html += f"            <tr><td class='code'>{violation['log_id']}</td><td class='timestamp'>{violation['timestamp']}</td><td class='ip-address'>{violation['ip']}</td><td>{violation['requests_per_minute']}</td></tr>\n"
        html += "        </table>\n"
    else:
        html += "        <p>No rate limit violations detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>2.6 User Agent Analysis</h2>

        <h3>Suspicious User Agents (Attack Tools)</h3>
"""
    if analysis['suspicious_user_agents']:
        html += "        <table>\n            <tr><th>Log ID</th><th>Timestamp</th><th>IP Address</th><th>Detected Tool</th><th>User Agent</th></tr>\n"
        for ua in analysis['suspicious_user_agents']:
            html += f"            <tr><td class='code'>{ua['log_id']}</td><td class='timestamp'>{ua['timestamp']}</td><td class='ip-address'>{ua['ip']}</td><td class='severity-high'>{ua['detected_tool']}</td><td>{ua['user_agent']}</td></tr>\n"
        html += "        </table>\n"
        html += """        <div class="alert alert-high">
            <strong>HIGH:</strong> Known attack tools detected in user agent strings. These IPs should be investigated and potentially blocked.
        </div>
"""
    else:
        html += "        <p>No suspicious user agents detected.</p>\n"

    html += """    </div>
</body>
</html>
"""
    with open(output_path, "w") as f:
        f.write(html)


def generate_performance_html_report(analysis: dict[str, Any], output_path: str) -> None:
    """Generate HTML report for performance analysis.

    Args:
        analysis: Performance analysis results.
        output_path: Path to save the HTML report.
    """
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Anomaly Analysis Report</title>
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
            color: #1976d2;
            border-bottom: 3px solid #1976d2;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #388e3c;
            margin-top: 30px;
        }}
        h3 {{
            color: #7b1fa2;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 15px;
            background: #e3f2fd;
            border-radius: 8px;
            min-width: 120px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #1976d2;
        }}
        .metric-label {{
            font-size: 0.85em;
            color: #666;
        }}
        .warning-metric {{
            background: #fff3e0;
        }}
        .warning-metric .metric-value {{
            color: #f57c00;
        }}
        .danger-metric {{
            background: #ffebee;
        }}
        .danger-metric .metric-value {{
            color: #d32f2f;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #388e3c;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .slow {{
            color: #d32f2f;
            font-weight: bold;
        }}
        .normal {{
            color: #388e3c;
        }}
        .anomaly {{
            background: #ffebee;
            border-left: 4px solid #d32f2f;
            padding: 15px;
            margin: 10px 0;
        }}
        .anomaly-critical {{
            border-left-color: #d32f2f;
        }}
        .anomaly-high {{
            border-left-color: #f57c00;
        }}
        .recommendation {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 10px 0;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        .code {{
            font-family: monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <h1>Performance Anomaly Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

    <div class="summary-card">
        <h2>3.1 Response Time Analysis - Overall Statistics</h2>
        <div class="metric">
            <div class="metric-value">{analysis['total_requests']}</div>
            <div class="metric-label">Total Requests</div>
        </div>
        <div class="metric">
            <div class="metric-value">{analysis['overall_stats']['avg']}ms</div>
            <div class="metric-label">Avg Response</div>
        </div>
        <div class="metric">
            <div class="metric-value">{analysis['overall_stats']['median']}ms</div>
            <div class="metric-label">Median</div>
        </div>
        <div class="metric warning-metric">
            <div class="metric-value">{analysis['overall_stats']['p95']}ms</div>
            <div class="metric-label">P95</div>
        </div>
        <div class="metric danger-metric">
            <div class="metric-value">{analysis['overall_stats']['p99']}ms</div>
            <div class="metric-label">P99</div>
        </div>
        <div class="metric danger-metric">
            <div class="metric-value">{analysis['slow_request_count']}</div>
            <div class="metric-label">Slow Requests (&gt;1s)</div>
        </div>
    </div>

    <div class="summary-card">
        <h2>Detected Anomalies</h2>
"""
    if analysis['anomalies']:
        for anomaly in analysis['anomalies']:
            severity_class = f"anomaly-{anomaly['severity'].lower()}"
            html += f"""        <div class="anomaly {severity_class}">
            <strong>{anomaly['severity']}: {anomaly['type']}</strong><br>
            {anomaly['details']}
        </div>
"""
    else:
        html += "        <p>No critical anomalies detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>Response Time by Endpoint</h2>
        <table>
            <tr><th>Endpoint</th><th>Requests</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Max (ms)</th><th>Slow Requests</th></tr>
"""
    sorted_endpoints = sorted(
        analysis['endpoint_stats'].items(),
        key=lambda x: x[1]['avg'],
        reverse=True
    )
    for endpoint, stats in sorted_endpoints:
        slow_class = "slow" if stats['avg'] > 1000 else "normal"
        html += f"            <tr><td>{endpoint}</td><td>{stats['request_count']}</td><td class='{slow_class}'>{stats['avg']}</td><td>{stats['p95']}</td><td>{stats['p99']}</td><td>{stats['max']}</td><td>{stats['slow_requests']}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="summary-card">
        <h2>3.4 Service Health Analysis</h2>
        <table>
            <tr><th>Service</th><th>Requests</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Slow Requests</th></tr>
"""
    sorted_services = sorted(
        analysis['service_stats'].items(),
        key=lambda x: x[1]['avg'],
        reverse=True
    )
    for service, stats in sorted_services:
        slow_class = "slow" if stats['avg'] > 1000 else "normal"
        html += f"            <tr><td>{service}</td><td>{stats['request_count']}</td><td class='{slow_class}'>{stats['avg']}</td><td>{stats['p95']}</td><td>{stats['p99']}</td><td>{stats['slow_requests']}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="summary-card">
        <h2>3.2 Resource Utilization Analysis</h2>

        <h3>Memory Issues</h3>
"""
    if analysis['memory_issues']:
        html += "        <table>\n            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Message</th></tr>\n"
        for issue in analysis['memory_issues'][:10]:
            html += f"            <tr><td class='code'>{issue['log_id']}</td><td class='timestamp'>{issue['timestamp']}</td><td>{issue['service']}</td><td>{issue['message']}</td></tr>\n"
        html += "        </table>\n"
    else:
        html += "        <p>No memory issues detected.</p>\n"

    html += """
        <h3>Connection Pool Issues</h3>
"""
    if analysis['connection_issues']:
        html += "        <table>\n            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Message</th></tr>\n"
        for issue in analysis['connection_issues']:
            html += f"            <tr><td class='code'>{issue['log_id']}</td><td class='timestamp'>{issue['timestamp']}</td><td>{issue['service']}</td><td>{issue['message']}</td></tr>\n"
        html += "        </table>\n"
    else:
        html += "        <p>No connection pool issues detected.</p>\n"

    html += """    </div>

    <div class="summary-card">
        <h2>3.5 Capacity Planning Insights</h2>

        <h3>Peak Load Hours</h3>
        <table>
            <tr><th>Hour (UTC)</th><th>Request Count</th><th>Avg Response Time (ms)</th><th>Max Response Time (ms)</th></tr>
"""
    for peak in analysis['peak_hours']:
        html += f"            <tr><td>{peak['hour']}:00</td><td>{peak['request_count']}</td><td>{peak['avg_response_time']}</td><td>{peak['max_response_time']}</td></tr>\n"

    html += """        </table>

        <h3>Hourly Traffic Distribution</h3>
        <table>
            <tr><th>Hour (UTC)</th><th>Requests</th><th>Avg Response (ms)</th><th>Max Response (ms)</th></tr>
"""
    for hour, stats in sorted(analysis['hourly_stats'].items()):
        html += f"            <tr><td>{hour}:00</td><td>{stats['request_count']}</td><td>{stats['avg_response_time']}</td><td>{stats['max_response_time']}</td></tr>\n"

    html += """        </table>
    </div>

    <div class="summary-card">
        <h2>3.6 Performance Trends & Recommendations</h2>

        <h3>Slowest Endpoints (Require Optimization)</h3>
        <table>
            <tr><th>Endpoint</th><th>Avg Response (ms)</th><th>Request Count</th></tr>
"""
    for endpoint in analysis['slowest_endpoints']:
        html += f"            <tr><td>{endpoint['endpoint']}</td><td class='slow'>{endpoint['avg']}</td><td>{endpoint['request_count']}</td></tr>\n"

    html += """        </table>

        <div class="recommendation">
            <strong>Recommendations:</strong>
            <ul>
                <li>Investigate and optimize endpoints with average response times exceeding 1000ms</li>
                <li>Consider implementing caching for frequently accessed endpoints</li>
                <li>Review database queries for slow endpoints</li>
                <li>Consider horizontal scaling during peak hours</li>
                <li>Implement connection pooling optimizations for services with connection issues</li>
            </ul>
        </div>
    </div>

    <div class="summary-card">
        <h2>Slow Request Details</h2>
        <table>
            <tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Endpoint</th><th>Response Time (ms)</th><th>Status</th></tr>
"""
    for req in analysis['slow_requests'][:20]:
        html += f"            <tr><td class='code'>{req['log_id']}</td><td class='timestamp'>{req['timestamp']}</td><td>{req['service']}</td><td>{req['endpoint']}</td><td class='slow'>{req['response_time_ms']}</td><td>{req['status_code']}</td></tr>\n"

    html += """        </table>
    </div>
</body>
</html>
"""
    with open(output_path, "w") as f:
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
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elastic Logs Analysis Summary</title>
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
            color: #1565c0;
            border-bottom: 3px solid #1565c0;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2e7d32;
            margin-top: 30px;
        }}
        .summary-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card-header {{
            font-size: 1.2em;
            font-weight: bold;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        .card-error {{ border-left: 4px solid #d32f2f; }}
        .card-error .card-header {{ color: #d32f2f; }}
        .card-security {{ border-left: 4px solid #7b1fa2; }}
        .card-security .card-header {{ color: #7b1fa2; }}
        .card-performance {{ border-left: 4px solid #1976d2; }}
        .card-performance .card-header {{ color: #1976d2; }}
        .metric-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }}
        .metric-label {{
            color: #666;
        }}
        .metric-value {{
            font-weight: bold;
        }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #ffc107; }}
        .normal {{ color: #388e3c; }}
        .report-links {{
            margin-top: 20px;
        }}
        .report-link {{
            display: inline-block;
            padding: 10px 20px;
            margin: 5px;
            background: #1976d2;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }}
        .report-link:hover {{
            background: #1565c0;
        }}
        .timestamp {{
            color: #666;
            font-size: 0.9em;
        }}
        .key-findings {{
            background: #fff3e0;
            border-left: 4px solid #f57c00;
            padding: 15px;
            margin: 15px 0;
        }}
        .action-items {{
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 15px;
            margin: 15px 0;
        }}
    </style>
</head>
<body>
    <h1>Elastic Logs Analysis Summary</h1>
    <p class="timestamp">Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    <p>Log File: logs/elastic_logs_30_11_25.json</p>

    <div class="dashboard">
        <div class="card card-error">
            <div class="card-header">Error Analysis</div>
            <div class="metric-row">
                <span class="metric-label">Total Errors</span>
                <span class="metric-value critical">{error_analysis['total_errors']}</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Error Rate</span>
                <span class="metric-value">{error_analysis['error_rate']}%</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Most Affected Service</span>
                <span class="metric-value">{list(error_analysis['errors_by_service'].keys())[0] if error_analysis['errors_by_service'] else 'N/A'}</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Primary Error Type</span>
                <span class="metric-value">{list(error_analysis['errors_by_status'].keys())[0] if error_analysis['errors_by_status'] else 'N/A'}</span>
            </div>
        </div>

        <div class="card card-security">
            <div class="card-header">Security Analysis</div>
            <div class="metric-row">
                <span class="metric-label">Critical Issues</span>
                <span class="metric-value critical">{security_analysis['severity_summary']['critical']}</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">High Issues</span>
                <span class="metric-value high">{security_analysis['severity_summary']['high']}</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Failed Auth Attempts</span>
                <span class="metric-value">{security_analysis['failed_auth_attempts']}</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Injection Attempts</span>
                <span class="metric-value critical">{len(security_analysis['injection_attempts'])}</span>
            </div>
        </div>

        <div class="card card-performance">
            <div class="card-header">Performance Analysis</div>
            <div class="metric-row">
                <span class="metric-label">Avg Response Time</span>
                <span class="metric-value">{performance_analysis['overall_stats']['avg']}ms</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">P99 Response Time</span>
                <span class="metric-value high">{performance_analysis['overall_stats']['p99']}ms</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Slow Requests (&gt;1s)</span>
                <span class="metric-value">{performance_analysis['slow_request_count']}</span>
            </div>
            <div class="metric-row">
                <span class="metric-label">Memory Issues</span>
                <span class="metric-value">{len(performance_analysis['memory_issues'])}</span>
            </div>
        </div>
    </div>

    <div class="summary-card">
        <h2>Key Findings</h2>
        <div class="key-findings">
            <strong>Critical Issues Requiring Immediate Attention:</strong>
            <ul>
"""
    if security_analysis['injection_attempts']:
        html += f"                <li><strong>SQL Injection Attempts:</strong> {len(security_analysis['injection_attempts'])} detected - requires immediate investigation</li>\n"
    if security_analysis['severity_summary']['critical'] > 0:
        html += f"                <li><strong>Critical Security Events:</strong> {security_analysis['severity_summary']['critical']} critical security issues identified</li>\n"
    if error_analysis['error_rate'] > 5:
        html += f"                <li><strong>High Error Rate:</strong> {error_analysis['error_rate']}% of requests resulted in errors</li>\n"
    if performance_analysis['overall_stats']['p99'] > 5000:
        html += f"                <li><strong>Performance Degradation:</strong> P99 latency at {performance_analysis['overall_stats']['p99']}ms exceeds acceptable threshold</li>\n"
    if len(security_analysis['suspicious_user_agents']) > 0:
        html += f"                <li><strong>Attack Tools Detected:</strong> {len(security_analysis['suspicious_user_agents'])} requests from known attack tools</li>\n"

    html += """            </ul>
        </div>
    </div>

    <div class="summary-card">
        <h2>Recommended Actions</h2>
        <div class="action-items">
            <strong>Priority 1 - Immediate (within 24 hours):</strong>
            <ul>
                <li>Investigate and block IPs associated with SQL injection attempts</li>
                <li>Review and strengthen input validation on affected endpoints</li>
                <li>Implement rate limiting for suspicious IPs</li>
            </ul>

            <strong>Priority 2 - Short-term (within 1 week):</strong>
            <ul>
                <li>Optimize slow endpoints exceeding 1000ms response time</li>
                <li>Review and increase database connection pool sizes</li>
                <li>Implement circuit breakers for failing services</li>
            </ul>

            <strong>Priority 3 - Medium-term (within 1 month):</strong>
            <ul>
                <li>Implement comprehensive monitoring and alerting</li>
                <li>Review memory allocation for services with memory issues</li>
                <li>Consider horizontal scaling for peak load periods</li>
            </ul>
        </div>
    </div>

    <div class="summary-card">
        <h2>Detailed Reports</h2>
        <div class="report-links">
            <a href="error_analysis_report.html" class="report-link">Error Analysis Report</a>
            <a href="security_analysis_report.html" class="report-link">Security Analysis Report</a>
            <a href="performance_analysis_report.html" class="report-link">Performance Analysis Report</a>
        </div>
    </div>
</body>
</html>
"""
    with open(output_path, "w") as f:
        f.write(html)


def main() -> None:
    """Main function to run all analyses and generate reports."""
    log_file = "logs/elastic_logs_30_11_25.json"
    output_dir = "analysis"

    Path(output_dir).mkdir(exist_ok=True)

    print(f"Loading logs from {log_file}...")
    logs = load_logs(log_file)
    print(f"Loaded {len(logs)} log entries")

    print("\nTask 1: Running Error Pattern Analysis...")
    error_results = analyze_errors(logs)
    print(f"  - Found {error_results['total_errors']} errors ({error_results['error_rate']}% error rate)")

    print("\nTask 2: Running Security Issue Detection...")
    security_results = analyze_security(logs)
    print(f"  - Found {security_results['total_security_events']} security events")
    print(f"  - Critical: {security_results['severity_summary']['critical']}, "
          f"High: {security_results['severity_summary']['high']}")

    print("\nTask 3: Running Performance Anomaly Analysis...")
    performance_results = analyze_performance(logs)
    print(f"  - Avg response time: {performance_results['overall_stats']['avg']}ms")
    print(f"  - P99 response time: {performance_results['overall_stats']['p99']}ms")
    print(f"  - Slow requests: {performance_results['slow_request_count']}")

    print("\nGenerating HTML reports...")

    error_report_path = f"{output_dir}/error_analysis_report.html"
    generate_error_html_report(error_results, error_report_path)
    print(f"  - Error report: {error_report_path}")

    security_report_path = f"{output_dir}/security_analysis_report.html"
    generate_security_html_report(security_results, security_report_path)
    print(f"  - Security report: {security_report_path}")

    performance_report_path = f"{output_dir}/performance_analysis_report.html"
    generate_performance_html_report(performance_results, performance_report_path)
    print(f"  - Performance report: {performance_report_path}")

    summary_report_path = f"{output_dir}/analysis_summary.html"
    generate_summary_html_report(
        error_results, security_results, performance_results, summary_report_path
    )
    print(f"  - Summary report: {summary_report_path}")

    print("\nAnalysis complete! All reports saved to the analysis/ directory.")


if __name__ == "__main__":
    main()
