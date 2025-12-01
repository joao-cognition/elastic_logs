#!/usr/bin/env python3
"""
Unified Log Analysis Script.

This script runs all three log analyses (error, security, performance) using Devin's API.
It can be used directly or triggered by GitHub Actions.
"""

import argparse
import json
import os
import sys
from datetime import datetime

from devin_api import DevinAPIClient, save_analysis_result


def build_error_analysis_prompt(log_file: str) -> str:
    """Build the prompt for error pattern analysis."""
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

Please provide a detailed report with summary statistics, detailed findings, and prioritized recommendations.
Save your analysis report to the `analysis/` folder."""


def build_security_analysis_prompt(log_file: str) -> str:
    """Build the prompt for security issue detection."""
    return f"""Analyze the Elastic Logs in the repository for security issues.

Please perform the following security analysis on the log file at `{log_file}`:

1. **Authentication Analysis**: Identify authentication-related issues:
   - Failed login attempts and their frequency
   - Brute force attack patterns
   - Unusual authentication patterns

2. **Suspicious IP Detection**: Analyze client IP addresses:
   - Identify IPs with high failure rates
   - Look for known malicious IP patterns
   - Detect IPs attempting to access restricted resources

3. **Injection Attack Detection**: Look for injection attempts:
   - SQL injection patterns
   - XSS attempts
   - Command injection attempts

4. **Access Control Violations**: Identify unauthorized access attempts:
   - Attempts to access admin endpoints without authorization
   - 401/403 response patterns

5. **Rate Limiting Analysis**: Analyze request patterns:
   - IPs exceeding rate limits
   - Potential DDoS patterns

Please provide a detailed security report with findings categorized by severity.
Save your analysis report to the `analysis/` folder."""


def build_performance_analysis_prompt(log_file: str) -> str:
    """Build the prompt for performance anomaly analysis."""
    return f"""Analyze the Elastic Logs in the repository for performance anomalies.

Please perform the following performance analysis on the log file at `{log_file}`:

1. **Response Time Analysis**: Analyze HTTP response times:
   - Calculate average, median, p95, and p99 response times per endpoint
   - Identify endpoints with consistently slow response times
   - Detect response time spikes

2. **Resource Utilization Analysis**: Examine resource-related logs:
   - Memory usage patterns
   - CPU utilization spikes
   - Connection pool exhaustion events

3. **Database Performance**: Analyze database-related performance:
   - Slow query detection
   - Connection pool utilization

4. **Service Health Analysis**: Evaluate service health:
   - Service availability patterns
   - Circuit breaker activations

5. **Performance Trends**: Identify performance trends:
   - Degradation patterns over time
   - Correlation between different performance metrics

Please provide a detailed performance report with metrics and optimization recommendations.
Save your analysis report to the `analysis/` folder."""


def run_analysis(
    client: DevinAPIClient,
    analysis_type: str,
    prompt: str,
    log_file: str,
) -> dict:
    """
    Run a single analysis using Devin API.

    Args:
        client: DevinAPIClient instance.
        analysis_type: Type of analysis (error, security, performance).
        prompt: The analysis prompt.
        log_file: Path to the log file.

    Returns:
        Dictionary with session information.
    """
    print(f"\n{'='*60}")
    print(f"Starting {analysis_type.upper()} analysis...")
    print(f"{'='*60}")

    try:
        session = client.create_session(
            prompt=prompt,
            idempotency_key=f"{analysis_type}-analysis-{os.path.basename(log_file)}-{datetime.utcnow().strftime('%Y%m%d')}",
        )

        session_id = session.get("session_id")
        session_url = session.get("url")

        print("Session created successfully!")
        print(f"  Session ID: {session_id}")
        print(f"  Session URL: {session_url}")

        result_file = save_analysis_result(
            analysis_type=analysis_type,
            session_id=session_id,
            session_url=session_url,
            prompt=prompt,
        )
        print(f"  Result saved to: {result_file}")

        return {
            "analysis_type": analysis_type,
            "session_id": session_id,
            "session_url": session_url,
            "result_file": result_file,
            "status": "initiated",
        }

    except Exception as e:
        print(f"Error running {analysis_type} analysis: {e}")
        return {
            "analysis_type": analysis_type,
            "status": "failed",
            "error": str(e),
        }


def main() -> None:
    """Run all three log analyses using Devin API."""
    parser = argparse.ArgumentParser(
        description="Run all log analyses using Devin API"
    )
    parser.add_argument(
        "--log-file",
        default="logs/elastic_logs.json",
        help="Path to the log file to analyze",
    )
    parser.add_argument(
        "--analyses",
        nargs="+",
        choices=["error", "security", "performance", "all"],
        default=["all"],
        help="Which analyses to run",
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

    analyses_to_run = args.analyses
    if "all" in analyses_to_run:
        analyses_to_run = ["error", "security", "performance"]

    prompts = {
        "error": build_error_analysis_prompt(args.log_file),
        "security": build_security_analysis_prompt(args.log_file),
        "performance": build_performance_analysis_prompt(args.log_file),
    }

    results = []
    for analysis_type in analyses_to_run:
        result = run_analysis(
            client=client,
            analysis_type=analysis_type,
            prompt=prompts[analysis_type],
            log_file=args.log_file,
        )
        results.append(result)

    print(f"\n{'='*60}")
    print("ANALYSIS SUMMARY")
    print(f"{'='*60}")

    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "log_file": args.log_file,
        "analyses": results,
    }

    os.makedirs("analysis", exist_ok=True)
    summary_file = f"analysis/summary_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSummary saved to: {summary_file}")

    for result in results:
        status_icon = "[OK]" if result["status"] == "initiated" else "[FAIL]"
        print(f"  {status_icon} {result['analysis_type'].upper()}: {result.get('session_url', result.get('error', 'N/A'))}")

    failed = [r for r in results if r["status"] == "failed"]
    if failed:
        print(f"\nWarning: {len(failed)} analysis/analyses failed to start")
        sys.exit(1)

    print("\nAll analyses initiated successfully!")


if __name__ == "__main__":
    main()
