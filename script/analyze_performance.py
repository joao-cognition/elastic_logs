#!/usr/bin/env python3
"""
Performance Anomaly Analysis Script.

This script uses Devin's API to analyze Elastic Logs for performance anomalies,
including slow response times, high memory usage, and resource exhaustion.
"""

import argparse
import json
import os
import sys

from devin_api import DevinAPIClient, save_analysis_result


def build_performance_analysis_prompt(log_file: str) -> str:
    """
    Build the prompt for performance anomaly analysis.

    Args:
        log_file: Path to the log file to analyze.

    Returns:
        The analysis prompt string.
    """
    return f"""Analyze the Elastic Logs in the repository for performance anomalies.

Please perform the following performance analysis on the log file at `{log_file}`:

1. **Response Time Analysis**: Analyze HTTP response times:
   - Calculate average, median, p95, and p99 response times per endpoint
   - Identify endpoints with consistently slow response times
   - Detect response time spikes and their correlation with other events

2. **Resource Utilization Analysis**: Examine resource-related logs:
   - Memory usage patterns and potential memory leaks
   - CPU utilization spikes
   - Connection pool exhaustion events
   - Disk I/O latency issues

3. **Database Performance**: Analyze database-related performance:
   - Slow query detection
   - Connection pool utilization
   - Query timeout patterns

4. **Service Health Analysis**: Evaluate service health:
   - Service availability patterns
   - Circuit breaker activations
   - Upstream service failures

5. **Capacity Planning Insights**: Provide capacity-related insights:
   - Peak load times and patterns
   - Resource headroom analysis
   - Scaling recommendations

6. **Performance Trends**: Identify performance trends:
   - Degradation patterns over time
   - Correlation between different performance metrics
   - Seasonal or time-based patterns

Please provide a detailed performance report with:
- Executive summary of system performance
- Detailed metrics and statistics
- Performance bottleneck identification
- Prioritized optimization recommendations
- Capacity planning suggestions
- Alerting threshold recommendations

Save your analysis report to the `analysis/` folder with a descriptive filename."""


def main() -> None:
    """Run performance anomaly analysis using Devin API."""
    parser = argparse.ArgumentParser(
        description="Analyze Elastic Logs for performance anomalies using Devin API"
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

    prompt = build_performance_analysis_prompt(args.log_file)

    print("Creating Devin session for performance anomaly analysis...")
    try:
        session = client.create_session(
            prompt=prompt,
            idempotency_key=f"performance-analysis-{os.path.basename(args.log_file)}",
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
        analysis_type="performance",
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

    print("\nPerformance anomaly analysis initiated successfully!")


if __name__ == "__main__":
    main()
