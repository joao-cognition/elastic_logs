#!/usr/bin/env python3
"""
Security Issue Detection Script.

This script uses Devin's API to analyze Elastic Logs for security issues,
including failed authentication attempts, suspicious IPs, and injection attacks.
"""

import argparse
import json
import os
import sys

from devin_api import DevinAPIClient, save_analysis_result


def build_security_analysis_prompt(log_file: str) -> str:
    """
    Build the prompt for security issue detection.

    Args:
        log_file: Path to the log file to analyze.

    Returns:
        The analysis prompt string.
    """
    return f"""Analyze the Elastic Logs in the repository for security issues.

Please perform the following security analysis on the log file at `{log_file}`:

1. **Authentication Analysis**: Identify authentication-related issues:
   - Failed login attempts and their frequency
   - Brute force attack patterns (multiple failed attempts from same IP)
   - Unusual authentication patterns (time, location, user agent)

2. **Suspicious IP Detection**: Analyze client IP addresses:
   - Identify IPs with high failure rates
   - Look for known malicious IP patterns
   - Detect IPs attempting to access restricted resources

3. **Injection Attack Detection**: Look for injection attempts:
   - SQL injection patterns in request parameters
   - XSS (Cross-Site Scripting) attempts
   - Command injection attempts
   - Path traversal attempts

4. **Access Control Violations**: Identify unauthorized access attempts:
   - Attempts to access admin endpoints without authorization
   - 401/403 response patterns
   - Privilege escalation attempts

5. **Rate Limiting Analysis**: Analyze request patterns:
   - IPs exceeding rate limits
   - Potential DDoS patterns
   - Automated bot activity indicators

6. **User Agent Analysis**: Examine user agents for:
   - Known attack tools (sqlmap, nikto, etc.)
   - Suspicious or malformed user agents
   - Bot signatures

Please provide a detailed security report with:
- Executive summary of security posture
- Detailed findings categorized by severity (Critical, High, Medium, Low)
- Specific indicators of compromise (IOCs)
- Recommended immediate actions
- Long-term security improvements

Save your analysis report to the `analysis/` folder with a descriptive filename."""


def main() -> None:
    """Run security issue detection using Devin API."""
    parser = argparse.ArgumentParser(
        description="Analyze Elastic Logs for security issues using Devin API"
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

    prompt = build_security_analysis_prompt(args.log_file)

    print("Creating Devin session for security issue detection...")
    try:
        session = client.create_session(
            prompt=prompt,
            idempotency_key=f"security-analysis-{os.path.basename(args.log_file)}",
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
        analysis_type="security",
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

    print("\nSecurity issue detection initiated successfully!")


if __name__ == "__main__":
    main()
