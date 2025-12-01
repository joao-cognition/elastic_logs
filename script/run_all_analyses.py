#!/usr/bin/env python3
"""Run all three log analyses using Devin's API."""

import json
import os
import sys
from datetime import datetime
from typing import Any

import requests


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load log entries from a JSON file.

    Args:
        log_file: Path to the log file.

    Returns:
        List of log entries.
    """
    with open(log_file, "r") as f:
        return json.load(f)


def filter_error_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter logs to only include ERROR level entries."""
    return [log for log in logs if log.get("log", {}).get("level") == "ERROR"]


def filter_security_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter logs to identify security-related entries."""
    security_indicators = [
        "unauthorized",
        "injection",
        "failed login",
        "suspicious",
        "rate limit",
        "invalid",
        "blocked",
        "attack",
    ]

    security_logs = []
    for log in logs:
        message = log.get("message", "").lower()
        event_category = log.get("event", {}).get("category", "")
        has_threat = "threat" in log

        is_security_related = (
            any(indicator in message for indicator in security_indicators)
            or event_category == "authentication"
            or has_threat
        )

        if is_security_related:
            security_logs.append(log)

    return security_logs


def filter_performance_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter logs to identify performance-related entries."""
    performance_indicators = [
        "latency",
        "timeout",
        "memory",
        "cpu",
        "slow",
        "exhausted",
        "garbage collection",
        "disk",
        "queue",
        "spike",
    ]

    performance_logs = []
    for log in logs:
        message = log.get("message", "").lower()
        has_performance_data = "performance" in log

        is_performance_related = (
            any(indicator in message for indicator in performance_indicators)
            or has_performance_data
        )

        if is_performance_related:
            performance_logs.append(log)

    return performance_logs


def call_devin_api(prompt: str, api_key: str) -> dict[str, Any]:
    """Call Devin's API to create an analysis session.

    Args:
        prompt: The analysis prompt.
        api_key: Devin API key.

    Returns:
        API response data.
    """
    url = "https://api.devin.ai/v1/sessions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "prompt": prompt,
    }

    response = requests.post(url, headers=headers, json=payload, timeout=60)
    response.raise_for_status()
    return response.json()


def run_error_analysis(
    logs: list[dict[str, Any]], api_key: str, output_dir: str
) -> dict[str, Any]:
    """Run error log analysis."""
    error_logs = filter_error_logs(logs)
    if not error_logs:
        return {"status": "skipped", "reason": "No error logs found"}

    log_summary = json.dumps(error_logs, indent=2)
    prompt = f"""Analyze the following application error logs from an Elastic Log dataset.

Identify:
1. Common error patterns and their frequency
2. Services most affected by errors
3. Potential root causes for each error type
4. Recommended remediation steps

Error Logs:
{log_summary}

Provide a structured analysis report with actionable recommendations."""

    result = call_devin_api(prompt, api_key)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"error_analysis_{timestamp}.json")

    analysis_data = {
        "analysis_type": "application_errors",
        "timestamp": datetime.now().isoformat(),
        "error_count": len(error_logs),
        "devin_session": result,
        "analyzed_logs": error_logs,
    }

    with open(output_file, "w") as f:
        json.dump(analysis_data, f, indent=2)

    return {"status": "success", "file": output_file, "session": result}


def run_security_analysis(
    logs: list[dict[str, Any]], api_key: str, output_dir: str
) -> dict[str, Any]:
    """Run security log analysis."""
    security_logs = filter_security_logs(logs)
    if not security_logs:
        return {"status": "skipped", "reason": "No security logs found"}

    log_summary = json.dumps(security_logs, indent=2)
    prompt = f"""Analyze the following security-related logs from an Elastic Log dataset.

Identify:
1. Types of security threats detected
2. Source IPs involved in suspicious activities
3. Services targeted by security threats
4. Severity assessment for each threat type
5. Recommended security measures and mitigations

Security Logs:
{log_summary}

Provide a structured security analysis report."""

    result = call_devin_api(prompt, api_key)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"security_analysis_{timestamp}.json")

    analysis_data = {
        "analysis_type": "security_issues",
        "timestamp": datetime.now().isoformat(),
        "security_event_count": len(security_logs),
        "devin_session": result,
        "analyzed_logs": security_logs,
    }

    with open(output_file, "w") as f:
        json.dump(analysis_data, f, indent=2)

    return {"status": "success", "file": output_file, "session": result}


def run_performance_analysis(
    logs: list[dict[str, Any]], api_key: str, output_dir: str
) -> dict[str, Any]:
    """Run performance log analysis."""
    performance_logs = filter_performance_logs(logs)
    if not performance_logs:
        return {"status": "skipped", "reason": "No performance logs found"}

    log_summary = json.dumps(performance_logs, indent=2)
    prompt = f"""Analyze the following performance-related logs from an Elastic Log dataset.

Identify:
1. Performance bottlenecks and their patterns
2. Services experiencing performance degradation
3. Resource utilization issues (CPU, memory, disk I/O)
4. Latency patterns and their potential causes
5. Capacity planning recommendations

Performance Logs:
{log_summary}

Provide a structured performance analysis report."""

    result = call_devin_api(prompt, api_key)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"performance_analysis_{timestamp}.json")

    analysis_data = {
        "analysis_type": "performance_issues",
        "timestamp": datetime.now().isoformat(),
        "performance_event_count": len(performance_logs),
        "devin_session": result,
        "analyzed_logs": performance_logs,
    }

    with open(output_file, "w") as f:
        json.dump(analysis_data, f, indent=2)

    return {"status": "success", "file": output_file, "session": result}


def main() -> int:
    """Main function to run all log analyses.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    api_key = os.environ.get("DEVIN_API_KEY")
    if not api_key:
        print("Error: DEVIN_API_KEY environment variable not set")
        return 1

    log_file = sys.argv[1] if len(sys.argv) > 1 else "logs/elastic_logs.json"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "analysis"

    os.makedirs(output_dir, exist_ok=True)

    print(f"Loading logs from {log_file}...")
    logs = load_logs(log_file)
    print(f"Loaded {len(logs)} log entries")

    results = {}

    print("\n=== Running Error Analysis ===")
    results["error"] = run_error_analysis(logs, api_key, output_dir)
    print(f"Error analysis: {results['error']['status']}")

    print("\n=== Running Security Analysis ===")
    results["security"] = run_security_analysis(logs, api_key, output_dir)
    print(f"Security analysis: {results['security']['status']}")

    print("\n=== Running Performance Analysis ===")
    results["performance"] = run_performance_analysis(logs, api_key, output_dir)
    print(f"Performance analysis: {results['performance']['status']}")

    print("\n=== Summary ===")
    for analysis_type, result in results.items():
        if result["status"] == "success":
            session_url = result["session"].get("url", "N/A")
            print(f"{analysis_type}: {result['file']}")
            print(f"  Devin session: {session_url}")
        else:
            print(f"{analysis_type}: {result['status']} - {result.get('reason', '')}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
