"""Elastic Logs Analysis Script for logs/elastic_logs_29_11_25.json.

Generates HTML reports for error patterns, security issues, and performance anomalies.
"""

import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, median, stdev
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load and parse the JSON log file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entry dictionaries.
    """
    with open(log_file, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_errors(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive error pattern analysis.

    Args:
        logs: List of log entry dictionaries.

    Returns:
        Dictionary containing all error analysis results.
    """
    error_logs = [log for log in logs if log.get("level") == "ERROR"]
    all_logs = logs

    status_code_counts: Counter = Counter()
    service_error_counts: Counter = Counter()
    error_message_counts: Counter = Counter()
    error_by_endpoint: defaultdict[str, int] = defaultdict(int)
    error_by_hour: defaultdict[str, int] = defaultdict(int)
    error_details: list[dict[str, Any]] = []
    service_endpoint_errors: defaultdict[str, Counter] = defaultdict(Counter)
    error_cascade_candidates: list[dict[str, Any]] = []

    for log in error_logs:
        status = log.get("http", {}).get("status_code", "N/A")
        service = log.get("service", "unknown")
        message = log.get("message", "unknown")
        endpoint = log.get("http", {}).get("endpoint", "unknown")
        timestamp = log.get("@timestamp", "")
        response_time = log.get("http", {}).get("response_time_ms", 0)

        status_code_counts[status] += 1
        service_error_counts[service] += 1
        error_message_counts[message] += 1
        error_by_endpoint[endpoint] += 1
        service_endpoint_errors[service][endpoint] += 1

        if timestamp:
            hour = timestamp[11:13]
            error_by_hour[hour] += 1

        error_info = log.get("error", {})
        error_details.append({
            "log_id": log.get("log_id"),
            "timestamp": timestamp,
            "service": service,
            "status_code": status,
            "message": message,
            "endpoint": endpoint,
            "response_time_ms": response_time,
            "error_type": error_info.get("type", "N/A"),
            "stack_trace": error_info.get("stack_trace", "N/A"),
            "correlation_id": error_info.get("correlation_id", "N/A"),
            "host": log.get("host", "unknown"),
        })

    prev_error_time = None
    for detail in sorted(error_details, key=lambda x: x["timestamp"]):
        if prev_error_time:
            prev_dt = datetime.fromisoformat(prev_error_time.replace("Z", "+00:00"))
            curr_dt = datetime.fromisoformat(
                detail["timestamp"].replace("Z", "+00:00")
            )
            diff_minutes = (curr_dt - prev_dt).total_seconds() / 60
            if diff_minutes <= 10:
                error_cascade_candidates.append(detail)
        prev_error_time = detail["timestamp"]

    total_requests = len(all_logs)
    total_errors = len(error_logs)
    error_rate = (total_errors / total_requests * 100) if total_requests > 0 else 0

    endpoint_total: Counter = Counter()
    for log in all_logs:
        ep = log.get("http", {}).get("endpoint", "unknown")
        endpoint_total[ep] += 1

    endpoint_error_rates: dict[str, float] = {}
    for ep, err_count in error_by_endpoint.items():
        total = endpoint_total.get(ep, 1)
        endpoint_error_rates[ep] = round(err_count / total * 100, 2)

    return {
        "total_logs": total_requests,
        "total_errors": total_errors,
        "error_rate": round(error_rate, 2),
        "status_code_counts": dict(status_code_counts.most_common()),
        "service_error_counts": dict(service_error_counts.most_common()),
        "error_message_counts": dict(error_message_counts.most_common()),
        "error_by_endpoint": dict(
            sorted(error_by_endpoint.items(), key=lambda x: x[1], reverse=True)
        ),
        "error_by_hour": dict(sorted(error_by_hour.items())),
        "error_details": error_details,
        "error_cascade_candidates": error_cascade_candidates,
        "endpoint_error_rates": dict(
            sorted(endpoint_error_rates.items(), key=lambda x: x[1], reverse=True)
        ),
        "service_endpoint_errors": {
            svc: dict(eps.most_common()) for svc, eps in service_endpoint_errors.items()
        },
    }


def analyze_security(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive security issue detection.

    Args:
        logs: List of log entry dictionaries.

    Returns:
        Dictionary containing all security analysis results.
    """
    security_events: list[dict[str, Any]] = []
    auth_failures: list[dict[str, Any]] = []
    sql_injection_attempts: list[dict[str, Any]] = []
    unauthorized_access: list[dict[str, Any]] = []
    rate_limit_violations: list[dict[str, Any]] = []
    suspicious_user_agents: list[dict[str, Any]] = []
    ip_failure_counts: Counter = Counter()
    ip_requests: Counter = Counter()
    ip_status_codes: defaultdict[str, Counter] = defaultdict(Counter)
    status_401_403_logs: list[dict[str, Any]] = []
    rate_limit_429_logs: list[dict[str, Any]] = []
    sqlmap_requests: list[dict[str, Any]] = []
    known_malicious_ips = {"45.33.32.156", "185.220.101.1", "91.121.87.10", "10.0.0.99"}
    attack_tool_patterns = {"sqlmap", "nikto", "nmap", "burpsuite", "hydra", "dirbuster"}

    findings_by_severity: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)

    for log in logs:
        ip = log.get("client", {}).get("ip", "unknown")
        user_agent = log.get("client", {}).get("user_agent", "")
        status_code = log.get("http", {}).get("status_code", 0)
        security = log.get("security", {})
        message = log.get("message", "")
        endpoint = log.get("http", {}).get("endpoint", "")
        timestamp = log.get("@timestamp", "")
        service = log.get("service", "")

        ip_requests[ip] += 1
        ip_status_codes[ip][status_code] += 1

        if status_code in (401, 403):
            ip_failure_counts[ip] += 1
            status_401_403_logs.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "ip": ip,
                "status_code": status_code,
                "endpoint": endpoint,
                "service": service,
                "message": message,
                "user_agent": user_agent,
            })

        if status_code == 429:
            rate_limit_429_logs.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "ip": ip,
                "endpoint": endpoint,
                "service": service,
                "message": message,
            })

        ua_lower = user_agent.lower()
        for tool in attack_tool_patterns:
            if tool in ua_lower:
                sqlmap_requests.append({
                    "log_id": log.get("log_id"),
                    "timestamp": timestamp,
                    "ip": ip,
                    "endpoint": endpoint,
                    "service": service,
                    "user_agent": user_agent,
                    "status_code": status_code,
                    "tool": tool,
                })
                if log not in suspicious_user_agents:
                    suspicious_user_agents.append({
                        "log_id": log.get("log_id"),
                        "timestamp": timestamp,
                        "ip": ip,
                        "user_agent": user_agent,
                        "endpoint": endpoint,
                        "tool_detected": tool,
                    })
                break

        event_type = security.get("event_type", "")

        if event_type == "SQL_INJECTION_ATTEMPT":
            sql_injection_attempts.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "ip": ip,
                "endpoint": endpoint,
                "service": service,
                "payload": security.get("payload", ""),
                "user_agent": user_agent,
                "status_code": status_code,
            })
            findings_by_severity["Critical"].append({
                "type": "SQL Injection Attempt",
                "log_id": log.get("log_id"),
                "ip": ip,
                "details": f"Payload: {security.get('payload', '')}",
            })

        if event_type == "UNAUTHORIZED_ACCESS":
            unauthorized_access.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "ip": ip,
                "endpoint": endpoint,
                "service": service,
                "target_resource": security.get("target_resource", ""),
                "user_agent": user_agent,
                "status_code": status_code,
            })
            findings_by_severity["High"].append({
                "type": "Unauthorized Access Attempt",
                "log_id": log.get("log_id"),
                "ip": ip,
                "details": f"Target: {security.get('target_resource', '')}",
            })

        if event_type == "RATE_LIMIT_EXCEEDED":
            rate_limit_violations.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "ip": ip,
                "endpoint": endpoint,
                "service": service,
                "requests_per_minute": security.get("requests_per_minute", 0),
                "status_code": status_code,
            })
            findings_by_severity["Medium"].append({
                "type": "Rate Limit Exceeded",
                "log_id": log.get("log_id"),
                "ip": ip,
                "details": f"{security.get('requests_per_minute', 0)} req/min",
            })

        if ip in known_malicious_ips:
            findings_by_severity["High"].append({
                "type": "Known Malicious IP",
                "log_id": log.get("log_id"),
                "ip": ip,
                "details": f"Endpoint: {endpoint}, Status: {status_code}",
            })

    brute_force_ips = {
        ip: count for ip, count in ip_failure_counts.items() if count >= 2
    }

    malicious_ip_activity: dict[str, dict[str, Any]] = {}
    for ip in known_malicious_ips:
        if ip in ip_requests:
            malicious_ip_activity[ip] = {
                "total_requests": ip_requests[ip],
                "failure_count": ip_failure_counts.get(ip, 0),
                "status_codes": dict(ip_status_codes[ip]),
            }

    for ua_entry in suspicious_user_agents:
        findings_by_severity["Medium"].append({
            "type": "Attack Tool Detected",
            "log_id": ua_entry["log_id"],
            "ip": ua_entry["ip"],
            "details": f"Tool: {ua_entry['tool_detected']}, UA: {ua_entry['user_agent']}",
        })

    return {
        "total_logs": len(logs),
        "auth_failure_count": len(status_401_403_logs),
        "auth_failures": status_401_403_logs,
        "brute_force_ips": brute_force_ips,
        "sql_injection_attempts": sql_injection_attempts,
        "unauthorized_access": unauthorized_access,
        "rate_limit_violations": rate_limit_violations,
        "rate_limit_429_count": len(rate_limit_429_logs),
        "rate_limit_429_logs": rate_limit_429_logs,
        "suspicious_user_agents": suspicious_user_agents,
        "sqlmap_request_count": len(sqlmap_requests),
        "sqlmap_requests": sqlmap_requests,
        "known_malicious_ip_activity": malicious_ip_activity,
        "findings_by_severity": dict(findings_by_severity),
        "ip_failure_counts": dict(ip_failure_counts.most_common(20)),
    }


def analyze_performance(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Perform comprehensive performance anomaly analysis.

    Args:
        logs: List of log entry dictionaries.

    Returns:
        Dictionary containing all performance analysis results.
    """
    response_times: list[int] = []
    endpoint_times: defaultdict[str, list[int]] = defaultdict(list)
    service_times: defaultdict[str, list[int]] = defaultdict(list)
    slow_requests: list[dict[str, Any]] = []
    performance_warnings: list[dict[str, Any]] = []
    hourly_response_times: defaultdict[str, list[int]] = defaultdict(list)

    for log in logs:
        rt = log.get("http", {}).get("response_time_ms", 0)
        endpoint = log.get("http", {}).get("endpoint", "unknown")
        service = log.get("service", "unknown")
        timestamp = log.get("@timestamp", "")

        response_times.append(rt)
        endpoint_times[endpoint].append(rt)
        service_times[service].append(rt)

        if timestamp:
            hour = timestamp[11:13]
            hourly_response_times[hour].append(rt)

        if rt > 1000:
            slow_requests.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "service": service,
                "endpoint": endpoint,
                "response_time_ms": rt,
                "status_code": log.get("http", {}).get("status_code"),
                "host": log.get("host", "unknown"),
                "message": log.get("message", ""),
            })

        if log.get("performance"):
            perf = log["performance"]
            performance_warnings.append({
                "log_id": log.get("log_id"),
                "timestamp": timestamp,
                "service": service,
                "endpoint": endpoint,
                "message": log.get("message", ""),
                "response_time_ms": rt,
                "read_latency_ms": perf.get("read_latency_ms", 0),
                "write_latency_ms": perf.get("write_latency_ms", 0),
                "iops": perf.get("iops", 0),
            })

    sorted_rt = sorted(response_times)
    p95_idx = int(len(sorted_rt) * 0.95)
    p99_idx = int(len(sorted_rt) * 0.99)

    overall_stats = {
        "count": len(response_times),
        "min": min(response_times) if response_times else 0,
        "max": max(response_times) if response_times else 0,
        "avg": round(mean(response_times), 2) if response_times else 0,
        "median": round(median(response_times), 2) if response_times else 0,
        "stdev": round(stdev(response_times), 2) if len(response_times) > 1 else 0,
        "p95": sorted_rt[p95_idx] if sorted_rt else 0,
        "p99": sorted_rt[p99_idx] if sorted_rt else 0,
    }

    endpoint_stats: dict[str, dict[str, Any]] = {}
    for ep, times in endpoint_times.items():
        s_times = sorted(times)
        p95_i = int(len(s_times) * 0.95)
        p99_i = int(len(s_times) * 0.99)
        endpoint_stats[ep] = {
            "count": len(times),
            "min": min(times),
            "max": max(times),
            "avg": round(mean(times), 2),
            "median": round(median(times), 2),
            "p95": s_times[p95_i] if s_times else 0,
            "p99": s_times[p99_i] if s_times else 0,
        }

    service_stats: dict[str, dict[str, Any]] = {}
    for svc, times in service_times.items():
        s_times = sorted(times)
        p95_i = int(len(s_times) * 0.95)
        p99_i = int(len(s_times) * 0.99)
        service_stats[svc] = {
            "count": len(times),
            "min": min(times),
            "max": max(times),
            "avg": round(mean(times), 2),
            "median": round(median(times), 2),
            "p95": s_times[p95_i] if s_times else 0,
            "p99": s_times[p99_i] if s_times else 0,
        }

    hourly_stats: dict[str, dict[str, Any]] = {}
    for hour, times in sorted(hourly_response_times.items()):
        hourly_stats[hour] = {
            "count": len(times),
            "avg": round(mean(times), 2),
            "max": max(times),
            "slow_count": sum(1 for t in times if t > 1000),
        }

    slow_requests_sorted = sorted(
        slow_requests, key=lambda x: x["response_time_ms"], reverse=True
    )

    return {
        "overall_stats": overall_stats,
        "endpoint_stats": dict(
            sorted(endpoint_stats.items(), key=lambda x: x[1]["avg"], reverse=True)
        ),
        "service_stats": dict(
            sorted(service_stats.items(), key=lambda x: x[1]["avg"], reverse=True)
        ),
        "slow_requests_count": len(slow_requests),
        "top_10_slowest": slow_requests_sorted[:10],
        "performance_warnings": performance_warnings,
        "hourly_stats": hourly_stats,
    }


def generate_error_html(data: dict[str, Any]) -> str:
    """Generate HTML report for error analysis.

    Args:
        data: Error analysis results dictionary.

    Returns:
        HTML string for the error analysis report.
    """
    rows_status = ""
    for code, count in data["status_code_counts"].items():
        pct = round(count / data["total_errors"] * 100, 1) if data["total_errors"] else 0
        rows_status += f"<tr><td>{code}</td><td>{count}</td><td>{pct}%</td></tr>\n"

    rows_service = ""
    for svc, count in data["service_error_counts"].items():
        pct = round(count / data["total_errors"] * 100, 1) if data["total_errors"] else 0
        rows_service += f"<tr><td>{svc}</td><td>{count}</td><td>{pct}%</td></tr>\n"

    rows_message = ""
    for msg, count in data["error_message_counts"].items():
        pct = round(count / data["total_errors"] * 100, 1) if data["total_errors"] else 0
        rows_message += f"<tr><td>{msg}</td><td>{count}</td><td>{pct}%</td></tr>\n"

    rows_endpoint = ""
    for ep, count in data["error_by_endpoint"].items():
        rate = data["endpoint_error_rates"].get(ep, 0)
        rows_endpoint += f"<tr><td>{ep}</td><td>{count}</td><td>{rate}%</td></tr>\n"

    rows_hour = ""
    for hour, count in data["error_by_hour"].items():
        bar_width = min(count * 40, 400)
        rows_hour += (
            f"<tr><td>{hour}:00</td><td>{count}</td>"
            f"<td><div class='bar' style='width:{bar_width}px'></div></td></tr>\n"
        )

    rows_details = ""
    for err in data["error_details"]:
        severity_class = "critical" if err["status_code"] in (500, 503) else "high"
        rows_details += (
            f"<tr class='{severity_class}'>"
            f"<td>{err['log_id']}</td>"
            f"<td>{err['timestamp']}</td>"
            f"<td>{err['service']}</td>"
            f"<td>{err['status_code']}</td>"
            f"<td>{err['endpoint']}</td>"
            f"<td>{err['response_time_ms']}ms</td>"
            f"<td class='msg-cell'>{err['message']}</td>"
            f"<td><code>{err['stack_trace']}</code></td>"
            f"</tr>\n"
        )

    rows_cascade = ""
    for err in data["error_cascade_candidates"]:
        rows_cascade += (
            f"<tr><td>{err['log_id']}</td><td>{err['timestamp']}</td>"
            f"<td>{err['service']}</td><td>{err['message']}</td></tr>\n"
        )

    root_causes = _build_root_cause_section(data)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Error Analysis Report - elastic_logs_29_11_25</title>
<style>
  :root {{ --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745;
           --bg: #f8f9fa; --card-bg: #fff; --border: #dee2e6; --text: #212529; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ color: var(--critical); margin-bottom: 0.5rem; font-size: 2rem; }}
  h2 {{ color: #495057; margin: 2rem 0 1rem; padding-bottom: 0.5rem;
       border-bottom: 2px solid var(--critical); }}
  h3 {{ color: #6c757d; margin: 1.5rem 0 0.75rem; }}
  .meta {{ color: #6c757d; margin-bottom: 2rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                   gap: 1rem; margin: 1.5rem 0; }}
  .summary-card {{ background: var(--card-bg); border-radius: 8px; padding: 1.5rem;
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
  .summary-card .value {{ font-size: 2.5rem; font-weight: 700; }}
  .summary-card .label {{ color: #6c757d; font-size: 0.9rem; }}
  .critical .value {{ color: var(--critical); }}
  .high .value {{ color: var(--high); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card-bg);
           border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  th {{ background: #343a40; color: white; padding: 0.75rem 1rem; text-align: left;
       font-weight: 600; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:hover {{ background: #f1f3f5; }}
  tr.critical {{ background: #fff5f5; }}
  tr.high {{ background: #fff8f0; }}
  .bar {{ background: var(--critical); height: 20px; border-radius: 3px; }}
  .msg-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }}
  .root-cause {{ background: var(--card-bg); border-left: 4px solid var(--critical);
                 padding: 1rem 1.5rem; margin: 1rem 0; border-radius: 0 8px 8px 0;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  .root-cause h4 {{ color: var(--critical); margin-bottom: 0.5rem; }}
  .remediation {{ background: #d4edda; border-left: 4px solid var(--low);
                  padding: 0.75rem 1rem; margin: 0.5rem 0; border-radius: 0 4px 4px 0; }}
  .section {{ margin-bottom: 2.5rem; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: #6c757d; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Error Analysis Report</h1>
  <p class="meta">Log File: elastic_logs_29_11_25.json | Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

  <div class="summary-grid">
    <div class="summary-card"><div class="value">{data['total_logs']}</div><div class="label">Total Log Entries</div></div>
    <div class="summary-card critical"><div class="value">{data['total_errors']}</div><div class="label">Total Errors</div></div>
    <div class="summary-card high"><div class="value">{data['error_rate']}%</div><div class="label">Error Rate</div></div>
    <div class="summary-card"><div class="value">{len(data['error_cascade_candidates'])}</div><div class="label">Cascade Errors</div></div>
  </div>

  <div class="section">
    <h2>1. Error Frequency by HTTP Status Code</h2>
    <table><thead><tr><th>Status Code</th><th>Count</th><th>% of Errors</th></tr></thead>
    <tbody>{rows_status}</tbody></table>
  </div>

  <div class="section">
    <h2>2. Errors by Service</h2>
    <table><thead><tr><th>Service</th><th>Error Count</th><th>% of Errors</th></tr></thead>
    <tbody>{rows_service}</tbody></table>
  </div>

  <div class="section">
    <h2>3. Error Message Classification</h2>
    <table><thead><tr><th>Error Message</th><th>Count</th><th>% of Errors</th></tr></thead>
    <tbody>{rows_message}</tbody></table>
  </div>

  <div class="section">
    <h2>4. Errors by Endpoint</h2>
    <table><thead><tr><th>Endpoint</th><th>Error Count</th><th>Error Rate</th></tr></thead>
    <tbody>{rows_endpoint}</tbody></table>
  </div>

  <div class="section">
    <h2>5. Error Distribution Over Time</h2>
    <table><thead><tr><th>Hour (UTC)</th><th>Error Count</th><th>Distribution</th></tr></thead>
    <tbody>{rows_hour}</tbody></table>
  </div>

  <div class="section">
    <h2>6. Error Cascade Detection</h2>
    <p>Errors occurring within 10 minutes of a previous error (potential cascades):</p>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Message</th></tr></thead>
    <tbody>{rows_cascade}</tbody></table>
  </div>

  <div class="section">
    <h2>7. Root Cause Analysis &amp; Remediation</h2>
    {root_causes}
  </div>

  <div class="section">
    <h2>8. Detailed Error Log</h2>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Status</th>
    <th>Endpoint</th><th>Response Time</th><th>Message</th><th>Stack Trace</th></tr></thead>
    <tbody>{rows_details}</tbody></table>
  </div>

  <footer>Report generated by Elastic Logs Analysis Pipeline | Data period: 2025-11-29</footer>
</div>
</body></html>"""


def _build_root_cause_section(data: dict[str, Any]) -> str:
    """Build HTML for root cause analysis section.

    Args:
        data: Error analysis results dictionary.

    Returns:
        HTML string for root cause analysis section.
    """
    sections = ""
    msg_counts = data["error_message_counts"]

    if "Internal server error: database connection pool exhausted" in msg_counts:
        count = msg_counts["Internal server error: database connection pool exhausted"]
        sections += f"""
    <div class="root-cause">
      <h4>Database Connection Pool Exhaustion ({count} occurrences)</h4>
      <p><strong>Impact:</strong> Causes 500/503/504 errors with response times 12-27s.
         Multiple services affected including order-service, api-gateway, security-monitor.</p>
      <p><strong>Root Cause:</strong> Connection pool limit reached under load.
         Connections not being released properly or pool size too small for traffic volume.</p>
      <div class="remediation">
        <strong>Remediation:</strong>
        <ul>
          <li>Increase connection pool size (current likely 100, recommend 200+)</li>
          <li>Implement connection timeout and idle connection cleanup</li>
          <li>Add connection pool monitoring and alerting</li>
          <li>Review connection leak patterns in application code</li>
          <li>Consider implementing connection pooling middleware (e.g., PgBouncer)</li>
        </ul>
      </div>
    </div>"""

    if "Request timeout: upstream service unavailable" in msg_counts:
        count = msg_counts["Request timeout: upstream service unavailable"]
        sections += f"""
    <div class="root-cause">
      <h4>Upstream Service Unavailability ({count} occurrences)</h4>
      <p><strong>Impact:</strong> Returns 500/502/503 errors. Services cannot reach dependencies,
         causing cascading failures across the microservices architecture.</p>
      <p><strong>Root Cause:</strong> Downstream services becoming unresponsive due to
         resource exhaustion (likely related to DB pool exhaustion).</p>
      <div class="remediation">
        <strong>Remediation:</strong>
        <ul>
          <li>Implement circuit breaker pattern (e.g., Resilience4j)</li>
          <li>Add retry with exponential backoff for transient failures</li>
          <li>Configure proper timeout values for inter-service communication</li>
          <li>Implement health check endpoints and readiness probes</li>
          <li>Add fallback mechanisms for critical service calls</li>
        </ul>
      </div>
    </div>"""

    if "Internal server error: out of memory exception" in msg_counts:
        count = msg_counts["Internal server error: out of memory exception"]
        sections += f"""
    <div class="root-cause">
      <h4>Out of Memory Exceptions ({count} occurrences)</h4>
      <p><strong>Impact:</strong> Causes 503 errors with extreme response times (20-29s).
         Affects security-monitor and cache-service.</p>
      <p><strong>Root Cause:</strong> JVM heap exhaustion from memory leaks or
         insufficient heap allocation for workload.</p>
      <div class="remediation">
        <strong>Remediation:</strong>
        <ul>
          <li>Increase JVM heap size (-Xmx) based on actual usage patterns</li>
          <li>Profile memory usage to identify leaks (use tools like YourKit/JProfiler)</li>
          <li>Implement proper resource cleanup in try-with-resources blocks</li>
          <li>Add GC logging and monitoring for early detection</li>
          <li>Consider container memory limits alignment with JVM settings</li>
        </ul>
      </div>
    </div>"""

    if "Connection refused: service unreachable" in msg_counts:
        count = msg_counts["Connection refused: service unreachable"]
        sections += f"""
    <div class="root-cause">
      <h4>Service Unreachable - Connection Refused ({count} occurrences)</h4>
      <p><strong>Impact:</strong> Returns 503 errors. Services completely unable to
         establish connections to dependent services.</p>
      <p><strong>Root Cause:</strong> Target service is down, crashed, or network
         connectivity issues between services.</p>
      <div class="remediation">
        <strong>Remediation:</strong>
        <ul>
          <li>Implement service mesh for better traffic management (e.g., Istio)</li>
          <li>Add automatic service restart on failure (Kubernetes liveness probes)</li>
          <li>Configure proper resource limits to prevent OOM kills</li>
          <li>Implement graceful degradation for non-critical dependencies</li>
        </ul>
      </div>
    </div>"""

    return sections


def generate_security_html(data: dict[str, Any]) -> str:
    """Generate HTML report for security analysis.

    Args:
        data: Security analysis results dictionary.

    Returns:
        HTML string for the security analysis report.
    """
    rows_auth = ""
    for entry in data["auth_failures"][:20]:
        rows_auth += (
            f"<tr><td>{entry['log_id']}</td><td>{entry['timestamp']}</td>"
            f"<td>{entry['ip']}</td><td>{entry['status_code']}</td>"
            f"<td>{entry['endpoint']}</td><td>{entry['service']}</td>"
            f"<td class='msg-cell'>{entry['message']}</td></tr>\n"
        )

    rows_brute = ""
    for ip, count in sorted(
        data["brute_force_ips"].items(), key=lambda x: x[1], reverse=True
    ):
        rows_brute += f"<tr><td>{ip}</td><td>{count}</td></tr>\n"

    rows_sqli = ""
    for entry in data["sql_injection_attempts"]:
        rows_sqli += (
            f"<tr class='critical'><td>{entry['log_id']}</td>"
            f"<td>{entry['timestamp']}</td><td>{entry['ip']}</td>"
            f"<td>{entry['endpoint']}</td><td><code>{entry['payload']}</code></td>"
            f"<td>{entry['user_agent']}</td><td>{entry['status_code']}</td></tr>\n"
        )

    rows_unauth = ""
    for entry in data["unauthorized_access"]:
        rows_unauth += (
            f"<tr class='high'><td>{entry['log_id']}</td>"
            f"<td>{entry['timestamp']}</td><td>{entry['ip']}</td>"
            f"<td>{entry['endpoint']}</td>"
            f"<td>{entry['target_resource']}</td>"
            f"<td>{entry['status_code']}</td></tr>\n"
        )

    rows_ratelimit = ""
    for entry in data["rate_limit_violations"]:
        rows_ratelimit += (
            f"<tr><td>{entry['log_id']}</td><td>{entry['timestamp']}</td>"
            f"<td>{entry['ip']}</td><td>{entry['endpoint']}</td>"
            f"<td>{entry['requests_per_minute']}</td>"
            f"<td>{entry['status_code']}</td></tr>\n"
        )

    rows_429 = ""
    for entry in data["rate_limit_429_logs"]:
        rows_429 += (
            f"<tr><td>{entry['log_id']}</td><td>{entry['timestamp']}</td>"
            f"<td>{entry['ip']}</td><td>{entry['endpoint']}</td>"
            f"<td>{entry['service']}</td></tr>\n"
        )

    rows_ua = ""
    for entry in data["suspicious_user_agents"][:20]:
        rows_ua += (
            f"<tr class='medium'><td>{entry['log_id']}</td>"
            f"<td>{entry['timestamp']}</td><td>{entry['ip']}</td>"
            f"<td>{entry['user_agent']}</td><td>{entry['tool_detected']}</td>"
            f"<td>{entry['endpoint']}</td></tr>\n"
        )

    rows_malicious = ""
    for ip, info in data["known_malicious_ip_activity"].items():
        status_str = ", ".join(f"{k}: {v}" for k, v in info["status_codes"].items())
        rows_malicious += (
            f"<tr class='high'><td>{ip}</td><td>{info['total_requests']}</td>"
            f"<td>{info['failure_count']}</td><td>{status_str}</td></tr>\n"
        )

    rows_severity = ""
    for severity in ["Critical", "High", "Medium", "Low"]:
        findings = data["findings_by_severity"].get(severity, [])
        for f in findings:
            sev_class = severity.lower()
            rows_severity += (
                f"<tr class='{sev_class}'><td><span class='badge badge-{sev_class}'>"
                f"{severity}</span></td>"
                f"<td>{f['type']}</td><td>{f['log_id']}</td>"
                f"<td>{f['ip']}</td><td>{f['details']}</td></tr>\n"
            )

    critical_count = len(data["findings_by_severity"].get("Critical", []))
    high_count = len(data["findings_by_severity"].get("High", []))
    medium_count = len(data["findings_by_severity"].get("Medium", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Analysis Report - elastic_logs_29_11_25</title>
<style>
  :root {{ --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745;
           --bg: #f8f9fa; --card-bg: #fff; --border: #dee2e6; --text: #212529; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ color: var(--critical); margin-bottom: 0.5rem; font-size: 2rem; }}
  h2 {{ color: #495057; margin: 2rem 0 1rem; padding-bottom: 0.5rem;
       border-bottom: 2px solid var(--high); }}
  h3 {{ color: #6c757d; margin: 1.5rem 0 0.75rem; }}
  .meta {{ color: #6c757d; margin-bottom: 2rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 1rem; margin: 1.5rem 0; }}
  .summary-card {{ background: var(--card-bg); border-radius: 8px; padding: 1.5rem;
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
  .summary-card .value {{ font-size: 2.5rem; font-weight: 700; }}
  .summary-card .label {{ color: #6c757d; font-size: 0.9rem; }}
  .critical .value {{ color: var(--critical); }}
  .high .value {{ color: var(--high); }}
  .medium .value {{ color: var(--medium); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card-bg);
           border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  th {{ background: #343a40; color: white; padding: 0.75rem 1rem; text-align: left;
       font-weight: 600; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:hover {{ background: #f1f3f5; }}
  tr.critical {{ background: #fff5f5; }}
  tr.high {{ background: #fff8f0; }}
  tr.medium {{ background: #fffde7; }}
  .msg-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-size: 0.85rem; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem;
           font-weight: 600; color: white; }}
  .badge-critical {{ background: var(--critical); }}
  .badge-high {{ background: var(--high); }}
  .badge-medium {{ background: #e6a700; }}
  .badge-low {{ background: var(--low); }}
  .alert-box {{ background: #fff5f5; border: 2px solid var(--critical); border-radius: 8px;
               padding: 1.5rem; margin: 1.5rem 0; }}
  .alert-box h3 {{ color: var(--critical); }}
  .section {{ margin-bottom: 2.5rem; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: #6c757d; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Security Analysis Report</h1>
  <p class="meta">Log File: elastic_logs_29_11_25.json | Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

  <div class="summary-grid">
    <div class="summary-card"><div class="value">{data['total_logs']}</div><div class="label">Total Log Entries</div></div>
    <div class="summary-card critical"><div class="value">{critical_count}</div><div class="label">Critical Findings</div></div>
    <div class="summary-card high"><div class="value">{high_count}</div><div class="label">High Findings</div></div>
    <div class="summary-card medium"><div class="value">{medium_count}</div><div class="label">Medium Findings</div></div>
    <div class="summary-card"><div class="value">{data['auth_failure_count']}</div><div class="label">Auth Failures (401/403)</div></div>
    <div class="summary-card"><div class="value">{data['sqlmap_request_count']}</div><div class="label">Attack Tool Requests</div></div>
  </div>

  <div class="section">
    <h2>1. Severity Classification</h2>
    <table><thead><tr><th>Severity</th><th>Finding Type</th><th>Log ID</th><th>IP</th><th>Details</th></tr></thead>
    <tbody>{rows_severity}</tbody></table>
  </div>

  <div class="section">
    <h2>2. Authentication Failures (401/403)</h2>
    <p>Total auth failures: <strong>{data['auth_failure_count']}</strong></p>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Status</th>
    <th>Endpoint</th><th>Service</th><th>Message</th></tr></thead>
    <tbody>{rows_auth}</tbody></table>
  </div>

  <div class="section">
    <h2>3. Brute Force Detection</h2>
    <p>IPs with 2+ authentication failures (potential brute force):</p>
    <table><thead><tr><th>IP Address</th><th>Failure Count</th></tr></thead>
    <tbody>{rows_brute}</tbody></table>
  </div>

  <div class="section">
    <h2>4. SQL Injection Attempts</h2>
    <div class="alert-box">
      <h3>SQL Injection Detected: {len(data['sql_injection_attempts'])} attempts</h3>
      <p>Active SQL injection payloads found in request parameters.</p>
    </div>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Endpoint</th>
    <th>Payload</th><th>User Agent</th><th>Status</th></tr></thead>
    <tbody>{rows_sqli}</tbody></table>
  </div>

  <div class="section">
    <h2>5. Unauthorized Access Attempts</h2>
    <p>Attempts to access restricted resources (e.g., /admin/users):</p>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Endpoint</th>
    <th>Target Resource</th><th>Status</th></tr></thead>
    <tbody>{rows_unauth}</tbody></table>
  </div>

  <div class="section">
    <h2>6. Rate Limiting Analysis</h2>
    <h3>6a. Rate Limit Exceeded Events</h3>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Endpoint</th>
    <th>Req/Min</th><th>Status</th></tr></thead>
    <tbody>{rows_ratelimit}</tbody></table>

    <h3>6b. HTTP 429 (Too Many Requests)</h3>
    <p>Total 429 responses: <strong>{data['rate_limit_429_count']}</strong></p>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>Endpoint</th>
    <th>Service</th></tr></thead>
    <tbody>{rows_429}</tbody></table>
  </div>

  <div class="section">
    <h2>7. Suspicious User Agents</h2>
    <p>Detected known attack tools (sqlmap, nikto, etc.): <strong>{data['sqlmap_request_count']}</strong> requests</p>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>IP</th><th>User Agent</th>
    <th>Tool Detected</th><th>Endpoint</th></tr></thead>
    <tbody>{rows_ua}</tbody></table>
  </div>

  <div class="section">
    <h2>8. Known Malicious IP Activity</h2>
    <table><thead><tr><th>IP Address</th><th>Total Requests</th><th>Failures</th>
    <th>Status Code Distribution</th></tr></thead>
    <tbody>{rows_malicious}</tbody></table>
  </div>

  <footer>Report generated by Elastic Logs Analysis Pipeline | Data period: 2025-11-29</footer>
</div>
</body></html>"""


def generate_performance_html(data: dict[str, Any]) -> str:
    """Generate HTML report for performance analysis.

    Args:
        data: Performance analysis results dictionary.

    Returns:
        HTML string for the performance analysis report.
    """
    stats = data["overall_stats"]

    rows_endpoint = ""
    for ep, ep_stats in data["endpoint_stats"].items():
        rows_endpoint += (
            f"<tr><td>{ep}</td><td>{ep_stats['count']}</td>"
            f"<td>{ep_stats['min']}ms</td><td>{ep_stats['max']}ms</td>"
            f"<td>{ep_stats['avg']}ms</td><td>{ep_stats['median']}ms</td>"
            f"<td>{ep_stats['p95']}ms</td><td>{ep_stats['p99']}ms</td></tr>\n"
        )

    rows_service = ""
    for svc, svc_stats in data["service_stats"].items():
        rows_service += (
            f"<tr><td>{svc}</td><td>{svc_stats['count']}</td>"
            f"<td>{svc_stats['min']}ms</td><td>{svc_stats['max']}ms</td>"
            f"<td>{svc_stats['avg']}ms</td><td>{svc_stats['median']}ms</td>"
            f"<td>{svc_stats['p95']}ms</td><td>{svc_stats['p99']}ms</td></tr>\n"
        )

    rows_slow = ""
    for req in data["top_10_slowest"]:
        severity = "critical" if req["response_time_ms"] > 20000 else "high"
        rows_slow += (
            f"<tr class='{severity}'><td>{req['log_id']}</td>"
            f"<td>{req['timestamp']}</td><td>{req['service']}</td>"
            f"<td>{req['endpoint']}</td>"
            f"<td><strong>{req['response_time_ms']}ms</strong></td>"
            f"<td>{req['status_code']}</td><td>{req['host']}</td>"
            f"<td class='msg-cell'>{req['message']}</td></tr>\n"
        )

    rows_perf_warn = ""
    for warn in data["performance_warnings"]:
        rows_perf_warn += (
            f"<tr><td>{warn['log_id']}</td><td>{warn['timestamp']}</td>"
            f"<td>{warn['service']}</td><td>{warn['message']}</td>"
            f"<td>{warn['response_time_ms']}ms</td>"
            f"<td>{warn['read_latency_ms']}ms</td>"
            f"<td>{warn['write_latency_ms']}ms</td>"
            f"<td>{warn['iops']}</td></tr>\n"
        )

    rows_hourly = ""
    for hour, h_stats in data["hourly_stats"].items():
        bar_width = min(int(h_stats["avg"] / 50), 400)
        rows_hourly += (
            f"<tr><td>{hour}:00</td><td>{h_stats['count']}</td>"
            f"<td>{h_stats['avg']}ms</td><td>{h_stats['max']}ms</td>"
            f"<td>{h_stats['slow_count']}</td>"
            f"<td><div class='bar bar-perf' style='width:{bar_width}px'></div></td></tr>\n"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Performance Analysis Report - elastic_logs_29_11_25</title>
<style>
  :root {{ --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745;
           --primary: #0d6efd; --bg: #f8f9fa; --card-bg: #fff; --border: #dee2e6;
           --text: #212529; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1400px; margin: 0 auto; }}
  h1 {{ color: var(--primary); margin-bottom: 0.5rem; font-size: 2rem; }}
  h2 {{ color: #495057; margin: 2rem 0 1rem; padding-bottom: 0.5rem;
       border-bottom: 2px solid var(--primary); }}
  h3 {{ color: #6c757d; margin: 1.5rem 0 0.75rem; }}
  .meta {{ color: #6c757d; margin-bottom: 2rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                   gap: 1rem; margin: 1.5rem 0; }}
  .summary-card {{ background: var(--card-bg); border-radius: 8px; padding: 1.5rem;
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
  .summary-card .value {{ font-size: 2.5rem; font-weight: 700; }}
  .summary-card .label {{ color: #6c757d; font-size: 0.9rem; }}
  .critical .value {{ color: var(--critical); }}
  .high .value {{ color: var(--high); }}
  .primary .value {{ color: var(--primary); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card-bg);
           border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  th {{ background: #343a40; color: white; padding: 0.75rem 1rem; text-align: left;
       font-weight: 600; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }}
  tr:hover {{ background: #f1f3f5; }}
  tr.critical {{ background: #fff5f5; }}
  tr.high {{ background: #fff8f0; }}
  .msg-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .bar-perf {{ background: var(--primary); height: 20px; border-radius: 3px; }}
  .section {{ margin-bottom: 2.5rem; }}
  .insight-box {{ background: #e7f3ff; border-left: 4px solid var(--primary); padding: 1rem 1.5rem;
                  margin: 1rem 0; border-radius: 0 8px 8px 0; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: #6c757d; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Performance Analysis Report</h1>
  <p class="meta">Log File: elastic_logs_29_11_25.json | Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

  <div class="summary-grid">
    <div class="summary-card"><div class="value">{stats['count']}</div><div class="label">Total Requests</div></div>
    <div class="summary-card primary"><div class="value">{stats['avg']}ms</div><div class="label">Avg Response Time</div></div>
    <div class="summary-card"><div class="value">{stats['median']}ms</div><div class="label">Median Response Time</div></div>
    <div class="summary-card high"><div class="value">{stats['p95']}ms</div><div class="label">P95 Response Time</div></div>
    <div class="summary-card critical"><div class="value">{stats['p99']}ms</div><div class="label">P99 Response Time</div></div>
    <div class="summary-card critical"><div class="value">{data['slow_requests_count']}</div><div class="label">Slow Requests (&gt;1s)</div></div>
  </div>

  <div class="section">
    <h2>1. Overall Response Time Statistics</h2>
    <table>
      <thead><tr><th>Metric</th><th>Value</th></tr></thead>
      <tbody>
        <tr><td>Total Requests</td><td>{stats['count']}</td></tr>
        <tr><td>Minimum</td><td>{stats['min']}ms</td></tr>
        <tr><td>Maximum</td><td>{stats['max']}ms</td></tr>
        <tr><td>Average</td><td>{stats['avg']}ms</td></tr>
        <tr><td>Median</td><td>{stats['median']}ms</td></tr>
        <tr><td>Standard Deviation</td><td>{stats['stdev']}ms</td></tr>
        <tr><td>P95</td><td>{stats['p95']}ms</td></tr>
        <tr><td>P99</td><td>{stats['p99']}ms</td></tr>
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>2. Response Time by Endpoint</h2>
    <table><thead><tr><th>Endpoint</th><th>Requests</th><th>Min</th><th>Max</th>
    <th>Avg</th><th>Median</th><th>P95</th><th>P99</th></tr></thead>
    <tbody>{rows_endpoint}</tbody></table>
  </div>

  <div class="section">
    <h2>3. Response Time by Service</h2>
    <table><thead><tr><th>Service</th><th>Requests</th><th>Min</th><th>Max</th>
    <th>Avg</th><th>Median</th><th>P95</th><th>P99</th></tr></thead>
    <tbody>{rows_service}</tbody></table>
  </div>

  <div class="section">
    <h2>4. Top 10 Slowest Requests</h2>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Endpoint</th>
    <th>Response Time</th><th>Status</th><th>Host</th><th>Message</th></tr></thead>
    <tbody>{rows_slow}</tbody></table>
  </div>

  <div class="section">
    <h2>5. Performance Warnings (Disk I/O &amp; Database)</h2>
    <div class="insight-box">
      <strong>Insight:</strong> {len(data['performance_warnings'])} performance warning events detected,
      including disk I/O latency spikes, slow database queries, and high memory usage.
    </div>
    <table><thead><tr><th>Log ID</th><th>Timestamp</th><th>Service</th><th>Warning</th>
    <th>Response Time</th><th>Read Latency</th><th>Write Latency</th><th>IOPS</th></tr></thead>
    <tbody>{rows_perf_warn}</tbody></table>
  </div>

  <div class="section">
    <h2>6. Hourly Performance Distribution</h2>
    <table><thead><tr><th>Hour (UTC)</th><th>Requests</th><th>Avg Response</th>
    <th>Max Response</th><th>Slow (&gt;1s)</th><th>Distribution</th></tr></thead>
    <tbody>{rows_hourly}</tbody></table>
  </div>

  <footer>Report generated by Elastic Logs Analysis Pipeline | Data period: 2025-11-29</footer>
</div>
</body></html>"""


def generate_summary_html(
    error_data: dict[str, Any],
    security_data: dict[str, Any],
    performance_data: dict[str, Any],
) -> str:
    """Generate HTML summary report combining all analyses.

    Args:
        error_data: Error analysis results.
        security_data: Security analysis results.
        performance_data: Performance analysis results.

    Returns:
        HTML string for the summary report.
    """
    stats = performance_data["overall_stats"]
    critical_count = len(security_data["findings_by_severity"].get("Critical", []))
    high_count = len(security_data["findings_by_severity"].get("High", []))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Analysis Summary - elastic_logs_29_11_25</title>
<style>
  :root {{ --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745;
           --primary: #0d6efd; --bg: #f8f9fa; --card-bg: #fff; --border: #dee2e6;
           --text: #212529; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ color: #212529; margin-bottom: 0.5rem; font-size: 2rem; }}
  h2 {{ color: #495057; margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid #adb5bd; }}
  .meta {{ color: #6c757d; margin-bottom: 2rem; }}
  .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; margin: 1.5rem 0; }}
  .card {{ background: var(--card-bg); border-radius: 8px; padding: 1.5rem;
           box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
  .card h3 {{ margin-bottom: 1rem; }}
  .card-error {{ border-top: 4px solid var(--critical); }}
  .card-error h3 {{ color: var(--critical); }}
  .card-security {{ border-top: 4px solid var(--high); }}
  .card-security h3 {{ color: var(--high); }}
  .card-perf {{ border-top: 4px solid var(--primary); }}
  .card-perf h3 {{ color: var(--primary); }}
  .stat {{ display: flex; justify-content: space-between; padding: 0.5rem 0;
           border-bottom: 1px solid var(--border); }}
  .stat-label {{ color: #6c757d; }}
  .stat-value {{ font-weight: 700; }}
  .stat-critical {{ color: var(--critical); }}
  .stat-high {{ color: var(--high); }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; background: var(--card-bg);
           border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  th {{ background: #343a40; color: white; padding: 0.75rem 1rem; text-align: left; }}
  td {{ padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }}
  .priority-list {{ list-style: none; padding: 0; }}
  .priority-list li {{ padding: 0.75rem 1rem; margin: 0.5rem 0; border-radius: 6px; }}
  .priority-list .p-critical {{ background: #fff5f5; border-left: 4px solid var(--critical); }}
  .priority-list .p-high {{ background: #fff8f0; border-left: 4px solid var(--high); }}
  .priority-list .p-medium {{ background: #fffde7; border-left: 4px solid var(--medium); }}
  a {{ color: var(--primary); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
           color: #6c757d; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>Elastic Logs Analysis Summary</h1>
  <p class="meta">Log File: elastic_logs_29_11_25.json | Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')} | Period: 2025-11-29 10:00 - 18:15 UTC</p>

  <div class="grid-3">
    <div class="card card-error">
      <h3>Error Analysis</h3>
      <div class="stat"><span class="stat-label">Total Errors</span><span class="stat-value stat-critical">{error_data['total_errors']}</span></div>
      <div class="stat"><span class="stat-label">Error Rate</span><span class="stat-value">{error_data['error_rate']}%</span></div>
      <div class="stat"><span class="stat-label">Affected Services</span><span class="stat-value">{len(error_data['service_error_counts'])}</span></div>
      <div class="stat"><span class="stat-label">Cascade Errors</span><span class="stat-value">{len(error_data['error_cascade_candidates'])}</span></div>
      <div class="stat"><span class="stat-label">Top Error</span><span class="stat-value" style="font-size:0.8rem">DB Pool Exhausted</span></div>
      <p style="margin-top:1rem"><a href="error_analysis_report.html">View Full Report</a></p>
    </div>

    <div class="card card-security">
      <h3>Security Analysis</h3>
      <div class="stat"><span class="stat-label">Critical Findings</span><span class="stat-value stat-critical">{critical_count}</span></div>
      <div class="stat"><span class="stat-label">High Findings</span><span class="stat-value stat-high">{high_count}</span></div>
      <div class="stat"><span class="stat-label">Auth Failures</span><span class="stat-value">{security_data['auth_failure_count']}</span></div>
      <div class="stat"><span class="stat-label">SQL Injection Attempts</span><span class="stat-value stat-critical">{len(security_data['sql_injection_attempts'])}</span></div>
      <div class="stat"><span class="stat-label">Attack Tool Requests</span><span class="stat-value">{security_data['sqlmap_request_count']}</span></div>
      <p style="margin-top:1rem"><a href="security_analysis_report.html">View Full Report</a></p>
    </div>

    <div class="card card-perf">
      <h3>Performance Analysis</h3>
      <div class="stat"><span class="stat-label">Avg Response Time</span><span class="stat-value">{stats['avg']}ms</span></div>
      <div class="stat"><span class="stat-label">P95 Response Time</span><span class="stat-value">{stats['p95']}ms</span></div>
      <div class="stat"><span class="stat-label">P99 Response Time</span><span class="stat-value stat-critical">{stats['p99']}ms</span></div>
      <div class="stat"><span class="stat-label">Slow Requests (&gt;1s)</span><span class="stat-value stat-high">{performance_data['slow_requests_count']}</span></div>
      <div class="stat"><span class="stat-label">Perf Warnings</span><span class="stat-value">{len(performance_data['performance_warnings'])}</span></div>
      <p style="margin-top:1rem"><a href="performance_analysis_report.html">View Full Report</a></p>
    </div>
  </div>

  <h2>Priority Action Items</h2>
  <ul class="priority-list">
    <li class="p-critical"><strong>CRITICAL:</strong> Database connection pool exhaustion causing cascading failures. Increase pool size and implement connection management improvements immediately.</li>
    <li class="p-critical"><strong>CRITICAL:</strong> {len(security_data['sql_injection_attempts'])} SQL injection attempts detected with payload <code>' OR '1'='1</code>. Verify WAF rules and input validation.</li>
    <li class="p-high"><strong>HIGH:</strong> {len(security_data['unauthorized_access'])} unauthorized access attempts targeting /admin/users. Review access controls and implement IP blocking.</li>
    <li class="p-high"><strong>HIGH:</strong> Out of memory exceptions in security-monitor and cache-service. Increase JVM heap and investigate memory leaks.</li>
    <li class="p-high"><strong>HIGH:</strong> {security_data['sqlmap_request_count']} requests from sqlmap attack tool detected. Consider blocking known attack tool user agents at WAF level.</li>
    <li class="p-medium"><strong>MEDIUM:</strong> {performance_data['slow_requests_count']} requests exceeding 1s response time. Investigate disk I/O and database query optimization.</li>
    <li class="p-medium"><strong>MEDIUM:</strong> Rate limiting triggered {data_safe_count(security_data, 'rate_limit_violations')} times. Review rate limit thresholds and implement progressive rate limiting.</li>
  </ul>

  <h2>Reports Generated</h2>
  <table>
    <thead><tr><th>Report</th><th>File</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td>Error Analysis</td><td><a href="error_analysis_report.html">error_analysis_report.html</a></td><td>Error frequency, patterns, root cause analysis, and remediation</td></tr>
      <tr><td>Security Analysis</td><td><a href="security_analysis_report.html">security_analysis_report.html</a></td><td>Authentication, injection, access control, and threat detection</td></tr>
      <tr><td>Performance Analysis</td><td><a href="performance_analysis_report.html">performance_analysis_report.html</a></td><td>Response times, slow requests, and performance warnings</td></tr>
      <tr><td>Summary</td><td><a href="analysis_summary.html">analysis_summary.html</a></td><td>This report - consolidated overview and action items</td></tr>
    </tbody>
  </table>

  <footer>Report generated by Elastic Logs Analysis Pipeline | Data period: 2025-11-29</footer>
</div>
</body></html>"""


def data_safe_count(data: dict[str, Any], key: str) -> int:
    """Safely get the count of items in a data dictionary list.

    Args:
        data: Dictionary containing the data.
        key: Key to look up in the dictionary.

    Returns:
        Count of items in the list, or 0 if key not found.
    """
    return len(data.get(key, []))


def main() -> None:
    """Main entry point for the analysis script."""
    repo_root = Path(__file__).resolve().parent.parent
    log_file = repo_root / "logs" / "elastic_logs_29_11_25.json"
    output_dir = repo_root / "analysis"

    if not log_file.exists():
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading logs from {log_file}...")
    logs = load_logs(str(log_file))
    print(f"Loaded {len(logs)} log entries.")

    print("Running error analysis...")
    error_data = analyze_errors(logs)
    error_html = generate_error_html(error_data)
    error_path = output_dir / "error_analysis_report.html"
    error_path.write_text(error_html, encoding="utf-8")
    print(f"  Saved: {error_path}")

    print("Running security analysis...")
    security_data = analyze_security(logs)
    security_html = generate_security_html(security_data)
    security_path = output_dir / "security_analysis_report.html"
    security_path.write_text(security_html, encoding="utf-8")
    print(f"  Saved: {security_path}")

    print("Running performance analysis...")
    performance_data = analyze_performance(logs)
    performance_html = generate_performance_html(performance_data)
    performance_path = output_dir / "performance_analysis_report.html"
    performance_path.write_text(performance_html, encoding="utf-8")
    print(f"  Saved: {performance_path}")

    print("Generating summary report...")
    summary_html = generate_summary_html(error_data, security_data, performance_data)
    summary_path = output_dir / "analysis_summary.html"
    summary_path.write_text(summary_html, encoding="utf-8")
    print(f"  Saved: {summary_path}")

    print("\nAnalysis complete. Reports saved to:", output_dir)
    print(f"  - error_analysis_report.html ({error_data['total_errors']} errors found)")
    print(
        f"  - security_analysis_report.html "
        f"({len(security_data['sql_injection_attempts'])} SQLi attempts)"
    )
    print(
        f"  - performance_analysis_report.html "
        f"({performance_data['slow_requests_count']} slow requests)"
    )
    print("  - analysis_summary.html")


if __name__ == "__main__":
    main()
