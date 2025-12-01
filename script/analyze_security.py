#!/usr/bin/env python3
"""Analyze Elastic Logs for security issues using Devin's API."""

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


def filter_security_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter logs to identify security-related entries.

    Args:
        logs: List of all log entries.

    Returns:
        List of security-related log entries.
    """
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


def create_analysis_prompt(security_logs: list[dict[str, Any]]) -> str:
    """Create a prompt for Devin to analyze security logs.

    Args:
        security_logs: List of security-related log entries.

    Returns:
        Analysis prompt string.
    """
    log_summary = json.dumps(security_logs, indent=2)
    return f"""Analyze the following security-related logs from an Elastic Log dataset.

Identify:
1. Types of security threats detected (SQL injection, XSS, brute force, etc.)
2. Source IPs involved in suspicious activities
3. Services targeted by security threats
4. Severity assessment for each threat type
5. Recommended security measures and mitigations

Security Logs:
{log_summary}

Provide a structured security analysis report with:
- Threat classification
- Risk assessment
- Immediate action items
- Long-term security recommendations"""


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


def save_analysis_result(
    result: dict[str, Any], security_logs: list[dict[str, Any]], output_dir: str
) -> str:
    """Save analysis result to a file.

    Args:
        result: API response data.
        security_logs: The security logs that were analyzed.
        output_dir: Directory to save the result.

    Returns:
        Path to the saved file.
    """
    os.makedirs(output_dir, exist_ok=True)
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

    return output_file


def main() -> int:
    """Main function to run security log analysis.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    api_key = os.environ.get("DEVIN_API_KEY")
    if not api_key:
        print("Error: DEVIN_API_KEY environment variable not set")
        return 1

    log_file = sys.argv[1] if len(sys.argv) > 1 else "logs/elastic_logs.json"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "analysis"

    print(f"Loading logs from {log_file}...")
    logs = load_logs(log_file)

    print("Filtering security-related logs...")
    security_logs = filter_security_logs(logs)
    print(f"Found {len(security_logs)} security-related entries")

    if not security_logs:
        print("No security-related logs found to analyze")
        return 0

    print("Creating analysis prompt...")
    prompt = create_analysis_prompt(security_logs)

    print("Calling Devin API for security analysis...")
    result = call_devin_api(prompt, api_key)

    print("Saving analysis result...")
    output_file = save_analysis_result(result, security_logs, output_dir)
    print(f"Analysis saved to {output_file}")

    session_url = result.get("url", "N/A")
    print(f"Devin session URL: {session_url}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
