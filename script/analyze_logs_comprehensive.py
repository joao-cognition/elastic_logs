#!/usr/bin/env python3
"""Comprehensive Elastic Logs Analysis Script.

This script performs error pattern analysis, security issue detection,
and performance anomaly analysis on Elastic logs, generating HTML reports.

Following coding guidelines:
- Type hints for all functions
- Google-style docstrings
- Maximum 100 character line length
- Grouped imports (standard library, third-party, local)
"""

import json
import os
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ErrorAnalysis:
    """Container for error analysis results."""

    total_errors: int = 0
    errors_by_status_code: dict[int, int] = field(default_factory=dict)
    errors_by_service: dict[str, int] = field(default_factory=dict)
    errors_by_message_type: dict[str, int] = field(default_factory=dict)
    error_timeline: list[dict[str, Any]] = field(default_factory=list)
    error_cascades: list[dict[str, Any]] = field(default_factory=list)
    endpoint_error_rates: dict[str, dict[str, Any]] = field(default_factory=dict)
    root_causes: list[dict[str, Any]] = field(default_factory=list)
    impacted_services: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SecurityAnalysis:
    """Container for security analysis results."""

    failed_auth_attempts: list[dict[str, Any]] = field(default_factory=list)
    brute_force_candidates: list[dict[str, Any]] = field(default_factory=list)
    suspicious_ips: list[dict[str, Any]] = field(default_factory=list)
    sql_injection_attempts: list[dict[str, Any]] = field(default_factory=list)
    xss_attempts: list[dict[str, Any]] = field(default_factory=list)
    unauthorized_access: list[dict[str, Any]] = field(default_factory=list)
    rate_limit_violations: list[dict[str, Any]] = field(default_factory=list)
    suspicious_user_agents: list[dict[str, Any]] = field(default_factory=list)
    severity_summary: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class PerformanceAnalysis:
    """Container for performance analysis results."""

    response_time_stats: dict[str, dict[str, float]] = field(default_factory=dict)
    slow_endpoints: list[dict[str, Any]] = field(default_factory=list)
    memory_issues: list[dict[str, Any]] = field(default_factory=list)
    disk_io_issues: list[dict[str, Any]] = field(default_factory=list)
    db_issues: list[dict[str, Any]] = field(default_factory=list)
    service_health: dict[str, dict[str, Any]] = field(default_factory=dict)
    peak_load_times: list[dict[str, Any]] = field(default_factory=list)
    performance_trends: list[dict[str, Any]] = field(default_factory=list)


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load and parse JSON log file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entries as dictionaries.

    Raises:
        FileNotFoundError: If the log file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    with open(log_file, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_errors(logs: list[dict[str, Any]]) -> ErrorAnalysis:
    """Perform comprehensive error pattern analysis.

    Args:
        logs: List of log entries.

    Returns:
        ErrorAnalysis object containing all error analysis results.
    """
    analysis = ErrorAnalysis()
    error_logs = [log for log in logs if log.get("level") == "ERROR"]
    analysis.total_errors = len(error_logs)

    status_code_counts: Counter[int] = Counter()
    service_counts: Counter[str] = Counter()
    message_counts: Counter[str] = Counter()
    endpoint_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "errors": 0})

    for log in logs:
        endpoint = log.get("http", {}).get("endpoint", "unknown")
        endpoint_stats[endpoint]["total"] += 1

    for log in error_logs:
        status_code = log.get("http", {}).get("status_code", 0)
        service = log.get("service", "unknown")
        message = log.get("message", "unknown")
        endpoint = log.get("http", {}).get("endpoint", "unknown")

        status_code_counts[status_code] += 1
        service_counts[service] += 1
        message_counts[message] += 1
        endpoint_stats[endpoint]["errors"] += 1

        analysis.error_timeline.append({
            "timestamp": log.get("@timestamp"),
            "log_id": log.get("log_id"),
            "service": service,
            "status_code": status_code,
            "message": message,
            "error_type": log.get("error", {}).get("type"),
            "correlation_id": log.get("error", {}).get("correlation_id")
        })

    analysis.errors_by_status_code = dict(status_code_counts)
    analysis.errors_by_service = dict(service_counts)
    analysis.errors_by_message_type = dict(message_counts)

    for endpoint, stats in endpoint_stats.items():
        if stats["errors"] > 0:
            analysis.endpoint_error_rates[endpoint] = {
                "total_requests": stats["total"],
                "error_count": stats["errors"],
                "error_rate": round(stats["errors"] / stats["total"] * 100, 2)
            }

    analysis.root_causes = _identify_root_causes(error_logs)
    analysis.error_cascades = _detect_error_cascades(error_logs)
    analysis.impacted_services = _assess_service_impact(service_counts, len(logs))

    return analysis


def _identify_root_causes(error_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Identify potential root causes for error categories.

    Args:
        error_logs: List of error log entries.

    Returns:
        List of root cause analysis results.
    """
    root_causes = []
    message_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for log in error_logs:
        message = log.get("message", "unknown")
        message_groups[message].append(log)

    root_cause_mapping = {
        "database connection pool exhausted": {
            "cause": "Database connection pool is exhausted due to high load or connection leaks",
            "remediation": [
                "Increase connection pool size",
                "Implement connection pooling best practices",
                "Add connection timeout and retry logic",
                "Monitor and close idle connections"
            ]
        },
        "upstream service unavailable": {
            "cause": "Upstream service is down or unreachable",
            "remediation": [
                "Implement circuit breaker pattern",
                "Add retry logic with exponential backoff",
                "Set up health checks for upstream services",
                "Configure fallback mechanisms"
            ]
        },
        "out of memory exception": {
            "cause": "Application is running out of memory due to memory leaks or insufficient allocation",
            "remediation": [
                "Increase heap size allocation",
                "Profile application for memory leaks",
                "Implement proper garbage collection tuning",
                "Add memory monitoring and alerts"
            ]
        },
        "service unreachable": {
            "cause": "Network connectivity issues or service crash",
            "remediation": [
                "Check network configuration",
                "Verify service health and restart if needed",
                "Implement service discovery",
                "Add redundancy and load balancing"
            ]
        }
    }

    for message, logs_list in message_groups.items():
        for pattern, details in root_cause_mapping.items():
            if pattern in message.lower():
                root_causes.append({
                    "error_message": message,
                    "occurrence_count": len(logs_list),
                    "affected_services": list(set(log.get("service") for log in logs_list)),
                    "root_cause": details["cause"],
                    "remediation_steps": details["remediation"],
                    "sample_correlation_ids": [
                        log.get("error", {}).get("correlation_id")
                        for log in logs_list[:3]
                        if log.get("error", {}).get("correlation_id")
                    ]
                })
                break

    return root_causes


def _detect_error_cascades(error_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect error cascades where errors trigger other errors.

    Args:
        error_logs: List of error log entries.

    Returns:
        List of detected error cascades.
    """
    cascades = []
    sorted_errors = sorted(error_logs, key=lambda x: x.get("@timestamp", ""))

    for i in range(len(sorted_errors) - 1):
        current = sorted_errors[i]
        next_error = sorted_errors[i + 1]

        current_time = datetime.fromisoformat(current.get("@timestamp", "").replace("Z", "+00:00"))
        next_time = datetime.fromisoformat(next_error.get("@timestamp", "").replace("Z", "+00:00"))
        time_diff = (next_time - current_time).total_seconds()

        if time_diff <= 300:
            cascades.append({
                "trigger_error": {
                    "log_id": current.get("log_id"),
                    "service": current.get("service"),
                    "message": current.get("message"),
                    "timestamp": current.get("@timestamp")
                },
                "subsequent_error": {
                    "log_id": next_error.get("log_id"),
                    "service": next_error.get("service"),
                    "message": next_error.get("message"),
                    "timestamp": next_error.get("@timestamp")
                },
                "time_difference_seconds": time_diff
            })

    return cascades


def _assess_service_impact(
    service_counts: Counter[str],
    total_logs: int
) -> list[dict[str, Any]]:
    """Assess impact on services based on error counts.

    Args:
        service_counts: Counter of errors per service.
        total_logs: Total number of log entries.

    Returns:
        List of service impact assessments.
    """
    impacts = []
    for service, error_count in service_counts.most_common():
        impact_level = "Critical" if error_count >= 5 else "High" if error_count >= 3 else "Medium"
        impacts.append({
            "service": service,
            "error_count": error_count,
            "impact_level": impact_level,
            "percentage_of_total": round(error_count / total_logs * 100, 2)
        })
    return impacts


def analyze_security(logs: list[dict[str, Any]]) -> SecurityAnalysis:
    """Perform comprehensive security issue detection.

    Args:
        logs: List of log entries.

    Returns:
        SecurityAnalysis object containing all security analysis results.
    """
    analysis = SecurityAnalysis()
    analysis.severity_summary = {"Critical": [], "High": [], "Medium": [], "Low": []}

    ip_failure_counts: Counter[str] = Counter()
    ip_requests: dict[str, list[dict[str, Any]]] = defaultdict(list)

    known_attack_tools = ["sqlmap", "nikto", "nmap", "burp", "hydra", "metasploit"]
    suspicious_ip_prefixes = ["45.33.", "185.220."]

    for log in logs:
        client_ip = log.get("client", {}).get("ip", "")
        status_code = log.get("http", {}).get("status_code", 0)
        user_agent = log.get("client", {}).get("user_agent", "")
        security_info = log.get("security", {})
        message = log.get("message", "")

        ip_requests[client_ip].append(log)

        if status_code in [401, 403]:
            ip_failure_counts[client_ip] += 1
            analysis.failed_auth_attempts.append({
                "timestamp": log.get("@timestamp"),
                "log_id": log.get("log_id"),
                "ip": client_ip,
                "status_code": status_code,
                "endpoint": log.get("http", {}).get("endpoint"),
                "user_agent": user_agent
            })

        event_type = security_info.get("event_type", "")

        if event_type == "SQL_INJECTION_ATTEMPT" or "sql injection" in message.lower():
            finding = {
                "timestamp": log.get("@timestamp"),
                "log_id": log.get("log_id"),
                "ip": client_ip,
                "endpoint": log.get("http", {}).get("endpoint"),
                "payload": security_info.get("payload", "N/A"),
                "user_agent": user_agent
            }
            analysis.sql_injection_attempts.append(finding)
            analysis.severity_summary["Critical"].append({
                "type": "SQL Injection Attempt",
                **finding
            })

        if event_type == "UNAUTHORIZED_ACCESS":
            finding = {
                "timestamp": log.get("@timestamp"),
                "log_id": log.get("log_id"),
                "ip": client_ip,
                "target_resource": security_info.get("target_resource"),
                "endpoint": log.get("http", {}).get("endpoint"),
                "user_agent": user_agent
            }
            analysis.unauthorized_access.append(finding)
            analysis.severity_summary["High"].append({
                "type": "Unauthorized Access Attempt",
                **finding
            })

        if event_type == "RATE_LIMIT_EXCEEDED" or status_code == 429:
            finding = {
                "timestamp": log.get("@timestamp"),
                "log_id": log.get("log_id"),
                "ip": client_ip,
                "requests_per_minute": security_info.get("requests_per_minute"),
                "endpoint": log.get("http", {}).get("endpoint")
            }
            analysis.rate_limit_violations.append(finding)
            analysis.severity_summary["Medium"].append({
                "type": "Rate Limit Violation",
                **finding
            })

        for tool in known_attack_tools:
            if tool.lower() in user_agent.lower():
                finding = {
                    "timestamp": log.get("@timestamp"),
                    "log_id": log.get("log_id"),
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "detected_tool": tool,
                    "endpoint": log.get("http", {}).get("endpoint")
                }
                if finding not in analysis.suspicious_user_agents:
                    analysis.suspicious_user_agents.append(finding)
                    analysis.severity_summary["High"].append({
                        "type": "Attack Tool Detected",
                        **finding
                    })
                break

        for prefix in suspicious_ip_prefixes:
            if client_ip.startswith(prefix):
                finding = {
                    "ip": client_ip,
                    "reason": f"IP from suspicious range ({prefix}x.x)",
                    "request_count": len(ip_requests[client_ip]),
                    "endpoints_accessed": list(set(
                        l.get("http", {}).get("endpoint") for l in ip_requests[client_ip]
                    ))
                }
                if not any(s["ip"] == client_ip for s in analysis.suspicious_ips):
                    analysis.suspicious_ips.append(finding)
                    analysis.severity_summary["Medium"].append({
                        "type": "Suspicious IP",
                        **finding
                    })
                break

    for ip, count in ip_failure_counts.items():
        if count >= 3:
            analysis.brute_force_candidates.append({
                "ip": ip,
                "failed_attempts": count,
                "severity": "Critical" if count >= 5 else "High",
                "timestamps": [
                    log.get("@timestamp")
                    for log in ip_requests[ip]
                    if log.get("http", {}).get("status_code") in [401, 403]
                ][:5]
            })
            analysis.severity_summary["Critical" if count >= 5 else "High"].append({
                "type": "Potential Brute Force Attack",
                "ip": ip,
                "failed_attempts": count
            })

    return analysis


def analyze_performance(logs: list[dict[str, Any]]) -> PerformanceAnalysis:
    """Perform comprehensive performance anomaly analysis.

    Args:
        logs: List of log entries.

    Returns:
        PerformanceAnalysis object containing all performance analysis results.
    """
    analysis = PerformanceAnalysis()

    endpoint_response_times: dict[str, list[int]] = defaultdict(list)
    service_stats: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"total": 0, "errors": 0, "response_times": []}
    )
    hourly_load: dict[str, int] = defaultdict(int)

    slow_threshold_ms = 1000

    for log in logs:
        endpoint = log.get("http", {}).get("endpoint", "unknown")
        service = log.get("service", "unknown")
        response_time = log.get("http", {}).get("response_time_ms", 0)
        timestamp = log.get("@timestamp", "")
        level = log.get("level", "")
        message = log.get("message", "")
        performance_info = log.get("performance", {})

        endpoint_response_times[endpoint].append(response_time)
        service_stats[service]["total"] += 1
        service_stats[service]["response_times"].append(response_time)
        if level == "ERROR":
            service_stats[service]["errors"] += 1

        if timestamp:
            hour = timestamp[:13]
            hourly_load[hour] += 1

        if response_time > slow_threshold_ms:
            analysis.slow_endpoints.append({
                "timestamp": timestamp,
                "log_id": log.get("log_id"),
                "endpoint": endpoint,
                "service": service,
                "response_time_ms": response_time,
                "severity": "Critical" if response_time > 10000 else "High"
            })

        if "memory" in message.lower() or "out of memory" in message.lower():
            analysis.memory_issues.append({
                "timestamp": timestamp,
                "log_id": log.get("log_id"),
                "service": service,
                "message": message,
                "correlation_id": log.get("error", {}).get("correlation_id")
            })

        if performance_info.get("read_latency_ms") or performance_info.get("write_latency_ms"):
            analysis.disk_io_issues.append({
                "timestamp": timestamp,
                "log_id": log.get("log_id"),
                "service": service,
                "read_latency_ms": performance_info.get("read_latency_ms"),
                "write_latency_ms": performance_info.get("write_latency_ms"),
                "iops": performance_info.get("iops"),
                "message": message
            })

        if "database" in message.lower() or "query" in message.lower():
            analysis.db_issues.append({
                "timestamp": timestamp,
                "log_id": log.get("log_id"),
                "service": service,
                "message": message,
                "response_time_ms": response_time
            })

    for endpoint, times in endpoint_response_times.items():
        if times:
            sorted_times = sorted(times)
            p95_idx = int(len(sorted_times) * 0.95)
            p99_idx = int(len(sorted_times) * 0.99)
            analysis.response_time_stats[endpoint] = {
                "min": min(times),
                "max": max(times),
                "avg": round(statistics.mean(times), 2),
                "median": round(statistics.median(times), 2),
                "p95": sorted_times[min(p95_idx, len(sorted_times) - 1)],
                "p99": sorted_times[min(p99_idx, len(sorted_times) - 1)],
                "request_count": len(times)
            }

    for service, stats in service_stats.items():
        error_rate = (stats["errors"] / stats["total"] * 100) if stats["total"] > 0 else 0
        avg_response = (
            statistics.mean(stats["response_times"]) if stats["response_times"] else 0
        )
        analysis.service_health[service] = {
            "total_requests": stats["total"],
            "error_count": stats["errors"],
            "error_rate": round(error_rate, 2),
            "avg_response_time_ms": round(avg_response, 2),
            "health_status": "Healthy" if error_rate < 5 else "Degraded" if error_rate < 15 else "Critical"
        }

    sorted_hours = sorted(hourly_load.items(), key=lambda x: x[1], reverse=True)
    analysis.peak_load_times = [
        {"hour": hour, "request_count": count}
        for hour, count in sorted_hours[:5]
    ]

    return analysis


def generate_error_html_report(analysis: ErrorAnalysis, output_path: str) -> None:
    """Generate HTML report for error analysis.

    Args:
        analysis: ErrorAnalysis object with results.
        output_path: Path to save the HTML report.
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Analysis Report</title>
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
            background: #e3f2fd;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #1976d2;
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
        .critical {{
            background-color: #ffebee;
            color: #c62828;
        }}
        .high {{
            background-color: #fff3e0;
            color: #e65100;
        }}
        .medium {{
            background-color: #fff8e1;
            color: #f57f17;
        }}
        .remediation {{
            background: #e8f5e9;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }}
        .remediation ul {{
            margin: 10px 0;
            padding-left: 20px;
        }}
        .timestamp {{
            font-family: monospace;
            font-size: 0.9em;
            color: #666;
        }}
    </style>
</head>
<body>
    <h1>Error Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().isoformat()}</p>

    <div class="summary-card">
        <h2>Executive Summary</h2>
        <div class="metric">
            <div class="metric-value">{analysis.total_errors}</div>
            <div class="metric-label">Total Errors</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(analysis.errors_by_service)}</div>
            <div class="metric-label">Services Affected</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(analysis.errors_by_status_code)}</div>
            <div class="metric-label">Error Types</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(analysis.error_cascades)}</div>
            <div class="metric-label">Error Cascades</div>
        </div>
    </div>

    <div class="summary-card">
        <h2>1. Error Frequency Analysis</h2>

        <h3>1.1 Errors by HTTP Status Code</h3>
        <table>
            <tr><th>Status Code</th><th>Count</th><th>Description</th></tr>
            {"".join(f"<tr><td>{code}</td><td>{count}</td><td>{_get_status_description(code)}</td></tr>"
                     for code, count in sorted(analysis.errors_by_status_code.items()))}
        </table>

        <h3>1.2 Errors by Service</h3>
        <table>
            <tr><th>Service</th><th>Error Count</th><th>Impact Level</th></tr>
            {"".join(f"<tr class='{_get_impact_class(count)}'><td>{service}</td><td>{count}</td><td>{_get_impact_level(count)}</td></tr>"
                     for service, count in sorted(analysis.errors_by_service.items(), key=lambda x: x[1], reverse=True))}
        </table>

        <h3>1.3 Errors by Message Type</h3>
        <table>
            <tr><th>Error Message</th><th>Count</th></tr>
            {"".join(f"<tr><td>{msg}</td><td>{count}</td></tr>"
                     for msg, count in sorted(analysis.errors_by_message_type.items(), key=lambda x: x[1], reverse=True))}
        </table>
    </div>

    <div class="summary-card">
        <h2>2. Root Cause Analysis</h2>
        {"".join(_format_root_cause_html(rc) for rc in analysis.root_causes)}
    </div>

    <div class="summary-card">
        <h2>3. Error Timeline</h2>
        <table>
            <tr><th>Timestamp</th><th>Log ID</th><th>Service</th><th>Status</th><th>Message</th></tr>
            {"".join(f"<tr><td class='timestamp'>{e['timestamp']}</td><td>{e['log_id']}</td><td>{e['service']}</td><td>{e['status_code']}</td><td>{e['message'][:50]}...</td></tr>"
                     for e in analysis.error_timeline[:20])}
        </table>
        <p><em>Showing first 20 errors. Total: {len(analysis.error_timeline)}</em></p>
    </div>

    <div class="summary-card">
        <h2>4. Error Cascades Detected</h2>
        {"".join(_format_cascade_html(c) for c in analysis.error_cascades[:10])}
        <p><em>Showing first 10 cascades. Total: {len(analysis.error_cascades)}</em></p>
    </div>

    <div class="summary-card">
        <h2>5. Endpoint Error Rates</h2>
        <table>
            <tr><th>Endpoint</th><th>Total Requests</th><th>Errors</th><th>Error Rate</th></tr>
            {"".join(f"<tr><td>{ep}</td><td>{stats['total_requests']}</td><td>{stats['error_count']}</td><td>{stats['error_rate']}%</td></tr>"
                     for ep, stats in sorted(analysis.endpoint_error_rates.items(), key=lambda x: x[1]['error_rate'], reverse=True))}
        </table>
    </div>

    <div class="summary-card">
        <h2>6. Service Impact Assessment</h2>
        <table>
            <tr><th>Service</th><th>Error Count</th><th>Impact Level</th><th>% of Total</th></tr>
            {"".join(f"<tr class='{impact['impact_level'].lower()}'><td>{impact['service']}</td><td>{impact['error_count']}</td><td>{impact['impact_level']}</td><td>{impact['percentage_of_total']}%</td></tr>"
                     for impact in analysis.impacted_services)}
        </table>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def _get_status_description(code: int) -> str:
    """Get description for HTTP status code."""
    descriptions = {
        500: "Internal Server Error",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout"
    }
    return descriptions.get(code, "Unknown Error")


def _get_impact_level(count: int) -> str:
    """Get impact level based on error count."""
    if count >= 5:
        return "Critical"
    elif count >= 3:
        return "High"
    else:
        return "Medium"


def _get_impact_class(count: int) -> str:
    """Get CSS class based on error count."""
    if count >= 5:
        return "critical"
    elif count >= 3:
        return "high"
    else:
        return "medium"


def _format_root_cause_html(rc: dict[str, Any]) -> str:
    """Format root cause as HTML."""
    return f"""
    <div class="remediation">
        <h3>{rc['error_message']}</h3>
        <p><strong>Occurrences:</strong> {rc['occurrence_count']}</p>
        <p><strong>Affected Services:</strong> {', '.join(rc['affected_services'])}</p>
        <p><strong>Root Cause:</strong> {rc['root_cause']}</p>
        <p><strong>Remediation Steps:</strong></p>
        <ul>
            {"".join(f"<li>{step}</li>" for step in rc['remediation_steps'])}
        </ul>
    </div>
    """


def _format_cascade_html(cascade: dict[str, Any]) -> str:
    """Format error cascade as HTML."""
    return f"""
    <div style="background: #fff3e0; padding: 10px; margin: 10px 0; border-radius: 5px;">
        <p><strong>Trigger:</strong> {cascade['trigger_error']['service']} - {cascade['trigger_error']['message'][:50]}...</p>
        <p><strong>Subsequent:</strong> {cascade['subsequent_error']['service']} - {cascade['subsequent_error']['message'][:50]}...</p>
        <p><strong>Time Difference:</strong> {cascade['time_difference_seconds']}s</p>
    </div>
    """


def generate_security_html_report(analysis: SecurityAnalysis, output_path: str) -> None:
    """Generate HTML report for security analysis.

    Args:
        analysis: SecurityAnalysis object with results.
        output_path: Path to save the HTML report.
    """
    total_findings = (
        len(analysis.sql_injection_attempts) +
        len(analysis.unauthorized_access) +
        len(analysis.rate_limit_violations) +
        len(analysis.brute_force_candidates)
    )

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
            color: #c62828;
            border-bottom: 3px solid #c62828;
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
            padding: 15px 25px;
            margin: 10px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-critical {{
            background: #ffebee;
        }}
        .metric-high {{
            background: #fff3e0;
        }}
        .metric-medium {{
            background: #fff8e1;
        }}
        .metric-low {{
            background: #e8f5e9;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
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
            background-color: #c62828;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .severity-critical {{
            background-color: #ffebee;
            border-left: 4px solid #c62828;
        }}
        .severity-high {{
            background-color: #fff3e0;
            border-left: 4px solid #e65100;
        }}
        .severity-medium {{
            background-color: #fff8e1;
            border-left: 4px solid #f57f17;
        }}
        .severity-low {{
            background-color: #e8f5e9;
            border-left: 4px solid #388e3c;
        }}
        .alert-box {{
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
        }}
        .timestamp {{
            font-family: monospace;
            font-size: 0.9em;
            color: #666;
        }}
        .ip-address {{
            font-family: monospace;
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().isoformat()}</p>

    <div class="summary-card">
        <h2>Executive Summary</h2>
        <div class="metric metric-critical">
            <div class="metric-value" style="color: #c62828;">{len(analysis.severity_summary.get('Critical', []))}</div>
            <div class="metric-label">Critical</div>
        </div>
        <div class="metric metric-high">
            <div class="metric-value" style="color: #e65100;">{len(analysis.severity_summary.get('High', []))}</div>
            <div class="metric-label">High</div>
        </div>
        <div class="metric metric-medium">
            <div class="metric-value" style="color: #f57f17;">{len(analysis.severity_summary.get('Medium', []))}</div>
            <div class="metric-label">Medium</div>
        </div>
        <div class="metric metric-low">
            <div class="metric-value" style="color: #388e3c;">{len(analysis.severity_summary.get('Low', []))}</div>
            <div class="metric-label">Low</div>
        </div>
        <p><strong>Total Security Findings:</strong> {total_findings}</p>
    </div>

    <div class="summary-card severity-critical">
        <h2>1. SQL Injection Attempts</h2>
        <p><strong>Total Detected:</strong> {len(analysis.sql_injection_attempts)}</p>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Payload</th></tr>
            {"".join(f"<tr><td class='timestamp'>{a['timestamp']}</td><td class='ip-address'>{a['ip']}</td><td>{a['endpoint']}</td><td><code>{a['payload']}</code></td></tr>"
                     for a in analysis.sql_injection_attempts[:10])}
        </table>
        <div class="alert-box" style="background: #ffebee;">
            <strong>Recommendation:</strong> Implement parameterized queries, input validation, and WAF rules to block SQL injection patterns.
        </div>
    </div>

    <div class="summary-card severity-high">
        <h2>2. Unauthorized Access Attempts</h2>
        <p><strong>Total Detected:</strong> {len(analysis.unauthorized_access)}</p>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Target Resource</th><th>Endpoint</th></tr>
            {"".join(f"<tr><td class='timestamp'>{a['timestamp']}</td><td class='ip-address'>{a['ip']}</td><td>{a['target_resource']}</td><td>{a['endpoint']}</td></tr>"
                     for a in analysis.unauthorized_access[:10])}
        </table>
        <div class="alert-box" style="background: #fff3e0;">
            <strong>Recommendation:</strong> Review access control policies, implement proper authentication, and monitor admin endpoint access.
        </div>
    </div>

    <div class="summary-card severity-critical">
        <h2>3. Potential Brute Force Attacks</h2>
        <p><strong>Suspicious IPs Detected:</strong> {len(analysis.brute_force_candidates)}</p>
        <table>
            <tr><th>IP Address</th><th>Failed Attempts</th><th>Severity</th></tr>
            {"".join(f"<tr class='severity-{b['severity'].lower()}'><td class='ip-address'>{b['ip']}</td><td>{b['failed_attempts']}</td><td>{b['severity']}</td></tr>"
                     for b in analysis.brute_force_candidates)}
        </table>
        <div class="alert-box" style="background: #ffebee;">
            <strong>Recommendation:</strong> Implement account lockout policies, CAPTCHA, and IP-based rate limiting.
        </div>
    </div>

    <div class="summary-card severity-medium">
        <h2>4. Rate Limit Violations</h2>
        <p><strong>Total Violations:</strong> {len(analysis.rate_limit_violations)}</p>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Requests/Min</th></tr>
            {"".join(f"<tr><td class='timestamp'>{r['timestamp']}</td><td class='ip-address'>{r['ip']}</td><td>{r['endpoint']}</td><td>{r['requests_per_minute']}</td></tr>"
                     for r in analysis.rate_limit_violations[:10])}
        </table>
    </div>

    <div class="summary-card severity-high">
        <h2>5. Suspicious User Agents (Attack Tools)</h2>
        <p><strong>Total Detected:</strong> {len(analysis.suspicious_user_agents)}</p>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Detected Tool</th><th>User Agent</th></tr>
            {"".join(f"<tr><td class='timestamp'>{u['timestamp']}</td><td class='ip-address'>{u['ip']}</td><td><strong>{u['detected_tool']}</strong></td><td>{u['user_agent']}</td></tr>"
                     for u in analysis.suspicious_user_agents[:10])}
        </table>
        <div class="alert-box" style="background: #fff3e0;">
            <strong>Recommendation:</strong> Block known attack tool signatures at WAF level and investigate source IPs.
        </div>
    </div>

    <div class="summary-card severity-medium">
        <h2>6. Suspicious IP Addresses</h2>
        <p><strong>Total Suspicious IPs:</strong> {len(analysis.suspicious_ips)}</p>
        <table>
            <tr><th>IP Address</th><th>Reason</th><th>Request Count</th><th>Endpoints Accessed</th></tr>
            {"".join(f"<tr><td class='ip-address'>{ip['ip']}</td><td>{ip['reason']}</td><td>{ip['request_count']}</td><td>{', '.join(ip['endpoints_accessed'][:3])}</td></tr>"
                     for ip in analysis.suspicious_ips)}
        </table>
    </div>

    <div class="summary-card">
        <h2>7. Failed Authentication Summary</h2>
        <p><strong>Total Failed Auth Attempts:</strong> {len(analysis.failed_auth_attempts)}</p>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Status Code</th><th>Endpoint</th></tr>
            {"".join(f"<tr><td class='timestamp'>{a['timestamp']}</td><td class='ip-address'>{a['ip']}</td><td>{a['status_code']}</td><td>{a['endpoint']}</td></tr>"
                     for a in analysis.failed_auth_attempts[:15])}
        </table>
    </div>

    <div class="summary-card">
        <h2>8. Severity Classification Summary</h2>
        <h3>Critical Findings ({len(analysis.severity_summary.get('Critical', []))})</h3>
        <ul>
            {"".join(f"<li>{f['type']}: {f.get('ip', 'N/A')}</li>" for f in analysis.severity_summary.get('Critical', [])[:5])}
        </ul>
        <h3>High Findings ({len(analysis.severity_summary.get('High', []))})</h3>
        <ul>
            {"".join(f"<li>{f['type']}: {f.get('ip', 'N/A')}</li>" for f in analysis.severity_summary.get('High', [])[:5])}
        </ul>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_performance_html_report(analysis: PerformanceAnalysis, output_path: str) -> None:
    """Generate HTML report for performance analysis.

    Args:
        analysis: PerformanceAnalysis object with results.
        output_path: Path to save the HTML report.
    """
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Performance Analysis Report</title>
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
            color: #ff6f00;
            border-bottom: 3px solid #ff6f00;
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
            background: #e3f2fd;
            padding: 15px 25px;
            margin: 10px;
            border-radius: 8px;
            text-align: center;
        }}
        .metric-warning {{
            background: #fff3e0;
        }}
        .metric-critical {{
            background: #ffebee;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #1976d2;
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
            background-color: #ff6f00;
            color: white;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .healthy {{
            background-color: #e8f5e9;
        }}
        .degraded {{
            background-color: #fff8e1;
        }}
        .critical {{
            background-color: #ffebee;
        }}
        .timestamp {{
            font-family: monospace;
            font-size: 0.9em;
            color: #666;
        }}
        .response-time {{
            font-family: monospace;
            font-weight: bold;
        }}
        .slow {{
            color: #c62828;
        }}
        .normal {{
            color: #388e3c;
        }}
    </style>
</head>
<body>
    <h1>Performance Analysis Report</h1>
    <p class="timestamp">Generated: {datetime.now().isoformat()}</p>

    <div class="summary-card">
        <h2>Executive Summary</h2>
        <div class="metric metric-critical">
            <div class="metric-value">{len(analysis.slow_endpoints)}</div>
            <div class="metric-label">Slow Requests (&gt;1s)</div>
        </div>
        <div class="metric metric-warning">
            <div class="metric-value">{len(analysis.memory_issues)}</div>
            <div class="metric-label">Memory Issues</div>
        </div>
        <div class="metric metric-warning">
            <div class="metric-value">{len(analysis.disk_io_issues)}</div>
            <div class="metric-label">Disk I/O Issues</div>
        </div>
        <div class="metric">
            <div class="metric-value">{len(analysis.db_issues)}</div>
            <div class="metric-label">Database Issues</div>
        </div>
    </div>

    <div class="summary-card">
        <h2>1. Response Time Analysis by Endpoint</h2>
        <table>
            <tr><th>Endpoint</th><th>Requests</th><th>Min (ms)</th><th>Avg (ms)</th><th>Median (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Max (ms)</th></tr>
            {"".join(f"<tr><td>{ep}</td><td>{stats['request_count']}</td><td>{stats['min']}</td><td class='response-time {'slow' if stats['avg'] > 1000 else 'normal'}'>{stats['avg']}</td><td>{stats['median']}</td><td>{stats['p95']}</td><td>{stats['p99']}</td><td class='response-time {'slow' if stats['max'] > 5000 else ''}'>{stats['max']}</td></tr>"
                     for ep, stats in sorted(analysis.response_time_stats.items(), key=lambda x: x[1]['avg'], reverse=True))}
        </table>
    </div>

    <div class="summary-card">
        <h2>2. Slow Endpoints (Response Time &gt; 1000ms)</h2>
        <table>
            <tr><th>Timestamp</th><th>Endpoint</th><th>Service</th><th>Response Time</th><th>Severity</th></tr>
            {"".join(f"<tr class='{s['severity'].lower()}'><td class='timestamp'>{s['timestamp']}</td><td>{s['endpoint']}</td><td>{s['service']}</td><td class='response-time slow'>{s['response_time_ms']}ms</td><td>{s['severity']}</td></tr>"
                     for s in sorted(analysis.slow_endpoints, key=lambda x: x['response_time_ms'], reverse=True)[:20])}
        </table>
        <p><em>Showing top 20 slowest requests. Total slow requests: {len(analysis.slow_endpoints)}</em></p>
    </div>

    <div class="summary-card">
        <h2>3. Service Health Overview</h2>
        <table>
            <tr><th>Service</th><th>Total Requests</th><th>Errors</th><th>Error Rate</th><th>Avg Response (ms)</th><th>Health Status</th></tr>
            {"".join(f"<tr class='{h['health_status'].lower()}'><td>{svc}</td><td>{h['total_requests']}</td><td>{h['error_count']}</td><td>{h['error_rate']}%</td><td class='response-time'>{h['avg_response_time_ms']}</td><td><strong>{h['health_status']}</strong></td></tr>"
                     for svc, h in sorted(analysis.service_health.items(), key=lambda x: x[1]['error_rate'], reverse=True))}
        </table>
    </div>

    <div class="summary-card">
        <h2>4. Memory Issues</h2>
        <p><strong>Total Memory-Related Issues:</strong> {len(analysis.memory_issues)}</p>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Message</th><th>Correlation ID</th></tr>
            {"".join(f"<tr><td class='timestamp'>{m['timestamp']}</td><td>{m['service']}</td><td>{m['message']}</td><td>{m['correlation_id']}</td></tr>"
                     for m in analysis.memory_issues)}
        </table>
        <div style="background: #fff3e0; padding: 15px; border-radius: 8px; margin-top: 10px;">
            <strong>Recommendation:</strong> Monitor heap usage, implement memory profiling, and consider increasing JVM heap size or optimizing memory-intensive operations.
        </div>
    </div>

    <div class="summary-card">
        <h2>5. Disk I/O Latency Issues</h2>
        <p><strong>Total Disk I/O Issues:</strong> {len(analysis.disk_io_issues)}</p>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Read Latency</th><th>Write Latency</th><th>IOPS</th><th>Message</th></tr>
            {"".join(f"<tr><td class='timestamp'>{d['timestamp']}</td><td>{d['service']}</td><td>{d['read_latency_ms']}ms</td><td>{d['write_latency_ms']}ms</td><td>{d['iops']}</td><td>{d['message']}</td></tr>"
                     for d in analysis.disk_io_issues)}
        </table>
    </div>

    <div class="summary-card">
        <h2>6. Database Performance Issues</h2>
        <p><strong>Total Database Issues:</strong> {len(analysis.db_issues)}</p>
        <table>
            <tr><th>Timestamp</th><th>Service</th><th>Message</th><th>Response Time</th></tr>
            {"".join(f"<tr><td class='timestamp'>{d['timestamp']}</td><td>{d['service']}</td><td>{d['message']}</td><td class='response-time slow'>{d['response_time_ms']}ms</td></tr>"
                     for d in analysis.db_issues)}
        </table>
        <div style="background: #fff3e0; padding: 15px; border-radius: 8px; margin-top: 10px;">
            <strong>Recommendation:</strong> Optimize slow queries, increase connection pool size, implement query caching, and consider database scaling.
        </div>
    </div>

    <div class="summary-card">
        <h2>7. Peak Load Times</h2>
        <table>
            <tr><th>Hour</th><th>Request Count</th></tr>
            {"".join(f"<tr><td class='timestamp'>{p['hour']}</td><td>{p['request_count']}</td></tr>"
                     for p in analysis.peak_load_times)}
        </table>
        <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin-top: 10px;">
            <strong>Capacity Planning:</strong> Consider auto-scaling policies during peak hours and ensure sufficient resources are provisioned.
        </div>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_summary_html_report(
    error_analysis: ErrorAnalysis,
    security_analysis: SecurityAnalysis,
    performance_analysis: PerformanceAnalysis,
    output_path: str
) -> None:
    """Generate summary HTML report combining all analyses.

    Args:
        error_analysis: ErrorAnalysis object with results.
        security_analysis: SecurityAnalysis object with results.
        performance_analysis: PerformanceAnalysis object with results.
        output_path: Path to save the HTML report.
    """
    total_security_findings = (
        len(security_analysis.sql_injection_attempts) +
        len(security_analysis.unauthorized_access) +
        len(security_analysis.brute_force_candidates)
    )

    html_content = f"""<!DOCTYPE html>
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
            color: #1976d2;
            border-bottom: 3px solid #1976d2;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #333;
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
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card-error {{
            border-left: 4px solid #d32f2f;
        }}
        .card-security {{
            border-left: 4px solid #c62828;
        }}
        .card-performance {{
            border-left: 4px solid #ff6f00;
        }}
        .card-title {{
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .card-value {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .card-error .card-value {{
            color: #d32f2f;
        }}
        .card-security .card-value {{
            color: #c62828;
        }}
        .card-performance .card-value {{
            color: #ff6f00;
        }}
        .findings-list {{
            list-style: none;
            padding: 0;
        }}
        .findings-list li {{
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
        }}
        .finding-critical {{
            background: #ffebee;
            border-left: 3px solid #c62828;
        }}
        .finding-high {{
            background: #fff3e0;
            border-left: 3px solid #e65100;
        }}
        .finding-medium {{
            background: #fff8e1;
            border-left: 3px solid #f57f17;
        }}
        .timestamp {{
            font-family: monospace;
            font-size: 0.9em;
            color: #666;
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
    </style>
</head>
<body>
    <h1>Elastic Logs Analysis Summary</h1>
    <p class="timestamp">Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    <p>Log File: logs/elastic_logs_29_11_25.json</p>

    <div class="dashboard">
        <div class="card card-error">
            <div class="card-title">Total Errors</div>
            <div class="card-value">{error_analysis.total_errors}</div>
            <p>{len(error_analysis.errors_by_service)} services affected</p>
        </div>
        <div class="card card-security">
            <div class="card-title">Security Findings</div>
            <div class="card-value">{total_security_findings}</div>
            <p>{len(security_analysis.severity_summary.get('Critical', []))} critical</p>
        </div>
        <div class="card card-performance">
            <div class="card-title">Slow Requests</div>
            <div class="card-value">{len(performance_analysis.slow_endpoints)}</div>
            <p>Response time &gt; 1000ms</p>
        </div>
    </div>

    <div class="summary-card">
        <h2>Error Analysis Highlights</h2>
        <ul class="findings-list">
            {"".join(f"<li class='finding-critical'><strong>{msg}:</strong> {count} occurrences</li>"
                     for msg, count in sorted(error_analysis.errors_by_message_type.items(), key=lambda x: x[1], reverse=True)[:5])}
        </ul>
        <h3>Most Affected Services</h3>
        <ul class="findings-list">
            {"".join(f"<li class='finding-high'><strong>{svc}:</strong> {count} errors</li>"
                     for svc, count in sorted(error_analysis.errors_by_service.items(), key=lambda x: x[1], reverse=True)[:5])}
        </ul>
    </div>

    <div class="summary-card">
        <h2>Security Analysis Highlights</h2>
        <h3>Critical Findings</h3>
        <ul class="findings-list">
            <li class="finding-critical"><strong>SQL Injection Attempts:</strong> {len(security_analysis.sql_injection_attempts)}</li>
            <li class="finding-critical"><strong>Brute Force Candidates:</strong> {len(security_analysis.brute_force_candidates)}</li>
            <li class="finding-high"><strong>Unauthorized Access Attempts:</strong> {len(security_analysis.unauthorized_access)}</li>
            <li class="finding-high"><strong>Attack Tools Detected:</strong> {len(security_analysis.suspicious_user_agents)}</li>
            <li class="finding-medium"><strong>Rate Limit Violations:</strong> {len(security_analysis.rate_limit_violations)}</li>
        </ul>
    </div>

    <div class="summary-card">
        <h2>Performance Analysis Highlights</h2>
        <h3>Resource Issues</h3>
        <ul class="findings-list">
            <li class="finding-critical"><strong>Memory Issues:</strong> {len(performance_analysis.memory_issues)}</li>
            <li class="finding-high"><strong>Disk I/O Issues:</strong> {len(performance_analysis.disk_io_issues)}</li>
            <li class="finding-high"><strong>Database Issues:</strong> {len(performance_analysis.db_issues)}</li>
        </ul>
        <h3>Service Health</h3>
        <ul class="findings-list">
            {"".join(f"<li class='finding-{'critical' if h['health_status'] == 'Critical' else 'high' if h['health_status'] == 'Degraded' else 'medium'}'><strong>{svc}:</strong> {h['health_status']} (Error Rate: {h['error_rate']}%)</li>"
                     for svc, h in sorted(performance_analysis.service_health.items(), key=lambda x: x[1]['error_rate'], reverse=True)[:5])}
        </ul>
    </div>

    <div class="summary-card">
        <h2>Recommendations</h2>
        <h3>Immediate Actions Required</h3>
        <ol>
            <li><strong>Address SQL Injection vulnerabilities</strong> - Implement parameterized queries and input validation</li>
            <li><strong>Investigate brute force attempts</strong> - Block suspicious IPs and implement account lockout</li>
            <li><strong>Resolve database connection pool issues</strong> - Increase pool size and implement connection management</li>
            <li><strong>Address memory issues</strong> - Profile application and optimize memory usage</li>
        </ol>
        <h3>Short-term Improvements</h3>
        <ol>
            <li>Implement circuit breaker pattern for upstream service calls</li>
            <li>Add WAF rules to block known attack tool signatures</li>
            <li>Set up monitoring and alerting for slow endpoints</li>
            <li>Review and optimize slow database queries</li>
        </ol>
    </div>

    <div class="summary-card">
        <h2>Detailed Reports</h2>
        <p>Click below to view detailed analysis reports:</p>
        <a href="error_analysis_report.html" class="report-link">Error Analysis Report</a>
        <a href="security_analysis_report.html" class="report-link">Security Analysis Report</a>
        <a href="performance_analysis_report.html" class="report-link">Performance Analysis Report</a>
    </div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def main() -> None:
    """Main function to run all analyses and generate reports."""
    import argparse

    parser = argparse.ArgumentParser(description="Comprehensive Elastic Logs Analysis")
    parser.add_argument(
        "--log-file",
        type=str,
        default="logs/elastic_logs_29_11_25.json",
        help="Path to the log file to analyze"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="analysis",
        help="Directory to save analysis reports"
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent.parent
    log_file = script_dir / args.log_file
    output_dir = script_dir / args.output_dir

    if not log_file.exists():
        log_file_alt = script_dir / "logs_to_be" / "elastic_logs_29_11_25.json"
        if log_file_alt.exists():
            log_file = log_file_alt
        else:
            raise FileNotFoundError(f"Log file not found: {log_file}")

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading logs from: {log_file}")
    logs = load_logs(str(log_file))
    print(f"Loaded {len(logs)} log entries")

    print("\nPerforming Error Analysis...")
    error_analysis = analyze_errors(logs)
    print(f"  - Total errors: {error_analysis.total_errors}")
    print(f"  - Services affected: {len(error_analysis.errors_by_service)}")

    print("\nPerforming Security Analysis...")
    security_analysis = analyze_security(logs)
    print(f"  - SQL injection attempts: {len(security_analysis.sql_injection_attempts)}")
    print(f"  - Unauthorized access attempts: {len(security_analysis.unauthorized_access)}")
    print(f"  - Brute force candidates: {len(security_analysis.brute_force_candidates)}")

    print("\nPerforming Performance Analysis...")
    performance_analysis = analyze_performance(logs)
    print(f"  - Slow endpoints: {len(performance_analysis.slow_endpoints)}")
    print(f"  - Memory issues: {len(performance_analysis.memory_issues)}")
    print(f"  - Database issues: {len(performance_analysis.db_issues)}")

    print("\nGenerating HTML Reports...")
    generate_error_html_report(
        error_analysis,
        str(output_dir / "error_analysis_report.html")
    )
    print(f"  - Error report: {output_dir / 'error_analysis_report.html'}")

    generate_security_html_report(
        security_analysis,
        str(output_dir / "security_analysis_report.html")
    )
    print(f"  - Security report: {output_dir / 'security_analysis_report.html'}")

    generate_performance_html_report(
        performance_analysis,
        str(output_dir / "performance_analysis_report.html")
    )
    print(f"  - Performance report: {output_dir / 'performance_analysis_report.html'}")

    generate_summary_html_report(
        error_analysis,
        security_analysis,
        performance_analysis,
        str(output_dir / "analysis_summary.html")
    )
    print(f"  - Summary report: {output_dir / 'analysis_summary.html'}")

    print("\nAnalysis complete!")


if __name__ == "__main__":
    main()
