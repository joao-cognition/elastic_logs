#!/usr/bin/env python3
"""
Error Pattern Analysis Script.

This script uses Devin's API to analyze Elastic Logs for error patterns,
including 500 errors, timeouts, and connection failures.
"""

import argparse
import json
import os
import sys

from devin_api import DevinAPIClient, save_analysis_result


def build_error_analysis_prompt(log_file: str) -> str:
    """
    Build the prompt for error pattern analysis.

    Args:
        log_file: Path to the log file to analyze.

    Returns:
        The analysis prompt string.
    """
    return f"""Analyze the Elastic Logs in the repository for error patterns.

Please perform the following analysis on the log file at `{log_file}`:

1. **Error Frequency Analysis**: Count and categorize all ERROR level logs by:
   - HTTP status code (500, 502, 503, 504, etc.)
   - Service name
   - Error message type

2. **Error Pattern Detection**: Identify recurring error patterns:
   - Look for repeated errors from the same service
   - Identify error cascades (errors that trigger other errors)
   - Find correlation between errors and specific endpoints

3. **Root Cause Analysis**: For each major error category:
   - Identify potential root causes based on error messages and stack traces
   - Suggest remediation steps

4. **Time-based Analysis**: Analyze error distribution over time:
   - Identify any error spikes or clusters
   - Look for patterns in error timing

5. **Impact Assessment**: Assess the impact of errors:
   - Which services are most affected
   - Which endpoints have the highest error rates
   - Estimate user impact based on error frequency

Please provide a detailed report with:
- Summary statistics
- Detailed findings for each analysis category
- Prioritized recommendations for addressing the errors
- Any anomalies or concerning patterns discovered

Save your analysis report to the `analysis/` folder with a descriptive filename."""


def main() -> None:
    """Run error pattern analysis using Devin API."""
    parser = argparse.ArgumentParser(
        description="Analyze Elastic Logs for error patterns using Devin API"
    )
    parser.add_argument(
        "--log-file",
        default="logs/elastic_logs.json",
        help="Path to the log file to analyze",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for analysis to complete",
    )
    args = parser.parse_args()

    if not os.path.exists(args.log_file):
        print(f"Error: Log file not found: {args.log_file}")
        sys.exit(1)

    print("Initializing Devin API client...")
    try:
        client = DevinAPIClient()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    prompt = build_error_analysis_prompt(args.log_file)

    print("Creating Devin session for error pattern analysis...")
    try:
        session = client.create_session(
            prompt=prompt,
            idempotency_key=f"error-analysis-{os.path.basename(args.log_file)}",
        )
    except Exception as e:
        print(f"Error creating session: {e}")
        sys.exit(1)

    session_id = session.get("session_id")
    session_url = session.get("url")

    print("Session created successfully!")
    print(f"  Session ID: {session_id}")
    print(f"  Session URL: {session_url}")

    result_file = save_analysis_result(
        analysis_type="error",
        session_id=session_id,
        session_url=session_url,
        prompt=prompt,
    )
    print(f"  Result saved to: {result_file}")

    if args.wait:
        print("\nWaiting for analysis to complete...")
        try:
            final_status = client.wait_for_completion(session_id)
            print(f"Analysis completed with status: {final_status.get('status_enum')}")

            with open(result_file, "r") as f:
                result = json.load(f)
            result["status"] = final_status.get("status_enum")
            result["final_response"] = final_status
            with open(result_file, "w") as f:
                json.dump(result, f, indent=2)

        except TimeoutError as e:
            print(f"Warning: {e}")

    print("\nError pattern analysis initiated successfully!")


if __name__ == "__main__":
    main()
