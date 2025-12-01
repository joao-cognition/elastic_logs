#!/usr/bin/env python3
"""Analyze Elastic Logs for performance issues using Devin's API."""

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


def filter_performance_logs(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter logs to identify performance-related entries.

    Args:
        logs: List of all log entries.

    Returns:
        List of performance-related log entries.
    """
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


def create_analysis_prompt(performance_logs: list[dict[str, Any]]) -> str:
    """Create a prompt for Devin to analyze performance logs.

    Args:
        performance_logs: List of performance-related log entries.

    Returns:
        Analysis prompt string.
    """
    log_summary = json.dumps(performance_logs, indent=2)
    return f"""Analyze the following performance-related logs from an Elastic Log dataset.

Identify:
1. Performance bottlenecks and their patterns
2. Services experiencing performance degradation
3. Resource utilization issues (CPU, memory, disk I/O)
4. Latency patterns and their potential causes
5. Capacity planning recommendations

Performance Logs:
{log_summary}

Provide a structured performance analysis report with:
- Performance metrics summary
- Bottleneck identification
- Resource optimization recommendations
- Scaling suggestions
- Monitoring improvements"""


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
    result: dict[str, Any], performance_logs: list[dict[str, Any]], output_dir: str
) -> str:
    """Save analysis result to a file.

    Args:
        result: API response data.
        performance_logs: The performance logs that were analyzed.
        output_dir: Directory to save the result.

    Returns:
        Path to the saved file.
    """
    os.makedirs(output_dir, exist_ok=True)
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

    return output_file


def main() -> int:
    """Main function to run performance log analysis.

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

    print("Filtering performance-related logs...")
    performance_logs = filter_performance_logs(logs)
    print(f"Found {len(performance_logs)} performance-related entries")

    if not performance_logs:
        print("No performance-related logs found to analyze")
        return 0

    print("Creating analysis prompt...")
    prompt = create_analysis_prompt(performance_logs)

    print("Calling Devin API for performance analysis...")
    result = call_devin_api(prompt, api_key)

    print("Saving analysis result...")
    output_file = save_analysis_result(result, performance_logs, output_dir)
    print(f"Analysis saved to {output_file}")

    session_url = result.get("url", "N/A")
    print(f"Devin session URL: {session_url}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
