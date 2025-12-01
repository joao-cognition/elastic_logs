#!/usr/bin/env python3
"""Analyze Elastic Logs for application errors using Devin's API."""

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
    """Filter logs to only include ERROR level entries.

    Args:
        logs: List of all log entries.

    Returns:
        List of error log entries.
    """
    return [log for log in logs if log.get("log", {}).get("level") == "ERROR"]


def create_analysis_prompt(error_logs: list[dict[str, Any]]) -> str:
    """Create a prompt for Devin to analyze error logs.

    Args:
        error_logs: List of error log entries.

    Returns:
        Analysis prompt string.
    """
    log_summary = json.dumps(error_logs, indent=2)
    return f"""Analyze the following application error logs from an Elastic Log dataset.

Identify:
1. Common error patterns and their frequency
2. Services most affected by errors
3. Potential root causes for each error type
4. Recommended remediation steps

Error Logs:
{log_summary}

Provide a structured analysis report with actionable recommendations."""


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
    result: dict[str, Any], error_logs: list[dict[str, Any]], output_dir: str
) -> str:
    """Save analysis result to a file.

    Args:
        result: API response data.
        error_logs: The error logs that were analyzed.
        output_dir: Directory to save the result.

    Returns:
        Path to the saved file.
    """
    os.makedirs(output_dir, exist_ok=True)
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

    return output_file


def main() -> int:
    """Main function to run error log analysis.

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

    print("Filtering error logs...")
    error_logs = filter_error_logs(logs)
    print(f"Found {len(error_logs)} error entries")

    if not error_logs:
        print("No error logs found to analyze")
        return 0

    print("Creating analysis prompt...")
    prompt = create_analysis_prompt(error_logs)

    print("Calling Devin API for error analysis...")
    result = call_devin_api(prompt, api_key)

    print("Saving analysis result...")
    output_file = save_analysis_result(result, error_logs, output_dir)
    print(f"Analysis saved to {output_file}")

    session_url = result.get("url", "N/A")
    print(f"Devin session URL: {session_url}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
