#!/usr/bin/env python3
"""
Playbook Runner Script.

This script triggers the Elastic Logs Analysis Playbook using Devin's API.
The playbook encapsulates all three analysis tasks (error, security, performance).
"""

import argparse
import json
import os
import sys
from datetime import datetime

from devin_api import DevinAPIClient


def build_playbook_prompt(log_file: str, output_dir: str) -> str:
    """
    Build the prompt that references the playbook for analysis.

    Args:
        log_file: Path to the log file to analyze.
        output_dir: Directory to save analysis results.

    Returns:
        The playbook execution prompt string.
    """
    return f"""Execute the Elastic Logs Analysis Playbook defined in playbook.yaml.

The playbook should analyze the log file at `{log_file}` and save results to `{output_dir}/`.

Please execute all three analysis tasks defined in the playbook:
1. Error Pattern Analysis - Identify and categorize errors
2. Security Issue Detection - Find security threats and vulnerabilities
3. Performance Anomaly Analysis - Detect performance bottlenecks

For each task:
- Follow the detailed instructions in the playbook
- Generate comprehensive reports
- Save results to the specified output directory

After completing all analyses, create a summary report at `{output_dir}/analysis_summary.md` that includes:
- Overview of findings from all three analyses
- Key metrics and statistics
- Prioritized recommendations
- Links to detailed reports"""


def main() -> None:
    """Run the Elastic Logs Analysis Playbook using Devin API."""
    parser = argparse.ArgumentParser(
        description="Run Elastic Logs Analysis Playbook using Devin API"
    )
    parser.add_argument(
        "--log-file",
        default="logs/elastic_logs.json",
        help="Path to the log file to analyze",
    )
    parser.add_argument(
        "--output-dir",
        default="analysis",
        help="Directory to save analysis results",
    )
    parser.add_argument(
        "--playbook-id",
        default=None,
        help="Optional Devin playbook ID to use",
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

    prompt = build_playbook_prompt(args.log_file, args.output_dir)

    print("Creating Devin session for playbook execution...")
    print(f"  Log file: {args.log_file}")
    print(f"  Output directory: {args.output_dir}")

    try:
        session_params = {
            "prompt": prompt,
            "idempotency_key": f"playbook-{os.path.basename(args.log_file)}-{datetime.utcnow().strftime('%Y%m%d')}",
        }

        if args.playbook_id:
            session_params["playbook_id"] = args.playbook_id
            print(f"  Using playbook ID: {args.playbook_id}")

        session = client.create_session(**session_params)

    except Exception as e:
        print(f"Error creating session: {e}")
        sys.exit(1)

    session_id = session.get("session_id")
    session_url = session.get("url")

    print("\nSession created successfully!")
    print(f"  Session ID: {session_id}")
    print(f"  Session URL: {session_url}")

    os.makedirs(args.output_dir, exist_ok=True)
    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "session_id": session_id,
        "session_url": session_url,
        "log_file": args.log_file,
        "output_dir": args.output_dir,
        "playbook_id": args.playbook_id,
        "status": "initiated",
    }

    result_file = f"{args.output_dir}/playbook_execution_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  Result saved to: {result_file}")

    if args.wait:
        print("\nWaiting for playbook execution to complete...")
        try:
            final_status = client.wait_for_completion(session_id)
            print(f"Playbook completed with status: {final_status.get('status_enum')}")

            result["status"] = final_status.get("status_enum")
            result["final_response"] = final_status
            with open(result_file, "w") as f:
                json.dump(result, f, indent=2)

        except TimeoutError as e:
            print(f"Warning: {e}")

    print("\nPlaybook execution initiated successfully!")
    print(f"Monitor progress at: {session_url}")


if __name__ == "__main__":
    main()
