#!/usr/bin/env python3
"""
Single script to run Elastic Logs analysis via Devin API.

This script provides a simple interface to analyze a specific log file
using Devin's API. It's designed for first-time users who want to quickly
run an analysis from their terminal.

Usage:
    python run_analysis.py <log_file>
    python run_analysis.py logs/sample_01_normal_traffic.json

Prerequisites:
    1. Set your DEVIN_API_KEY environment variable:
       export DEVIN_API_KEY="your-api-key-here"
    
    2. Install required dependencies:
       pip install requests

Example:
    export DEVIN_API_KEY="your-api-key-here"
    python run_analysis.py logs/sample_01_normal_traffic.json
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required.")
    print("Install it with: pip install requests")
    sys.exit(1)


class DevinAPIClient:
    """Simple client for interacting with Devin's API."""

    BASE_URL = "https://api.devin.ai/v1"

    def __init__(self, api_key: str) -> None:
        """Initialize the Devin API client."""
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    def create_session(
        self,
        prompt: str,
        playbook_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a new Devin session with the given prompt."""
        payload: dict[str, Any] = {"prompt": prompt}

        if playbook_id:
            payload["playbook_id"] = playbook_id

        response = requests.post(
            f"{self.BASE_URL}/sessions",
            headers=self.headers,
            json=payload,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()


def load_log_file(file_path: str) -> list[dict[str, Any]]:
    """Load and validate a log file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with open(file_path, "r") as f:
        logs = json.load(f)

    if not isinstance(logs, list):
        raise ValueError("Log file must contain a JSON array of log entries")

    return logs


def generate_analysis_prompt(file_path: str, logs: list[dict[str, Any]]) -> str:
    """Generate a comprehensive analysis prompt for the log file."""
    error_count = sum(1 for log in logs if log.get("level") == "ERROR")
    warn_count = sum(1 for log in logs if log.get("level") == "WARN")
    info_count = sum(1 for log in logs if log.get("level") == "INFO")

    services = set(log.get("service", "unknown") for log in logs)

    prompt = f"""Analyze the Elastic Log file at {file_path}.

Log File Summary:
- Total entries: {len(logs)}
- ERROR level: {error_count}
- WARN level: {warn_count}
- INFO level: {info_count}
- Services: {', '.join(sorted(services))}

Please perform a comprehensive analysis covering:

1. ERROR PATTERN ANALYSIS:
   - Identify and categorize all ERROR level logs
   - Find recurring error patterns
   - Determine root causes and suggest remediation

2. SECURITY ISSUE DETECTION:
   - Look for authentication failures
   - Detect suspicious IP addresses and user agents
   - Identify potential injection attacks (SQL, XSS)
   - Flag unauthorized access attempts

3. PERFORMANCE ANOMALY ANALYSIS:
   - Analyze response times and identify slow endpoints
   - Detect resource utilization issues
   - Find performance bottlenecks

Save your analysis results to the 'analysis/' directory with detailed reports.
"""
    return prompt


def main() -> None:
    """Main entry point for the analysis script."""
    parser = argparse.ArgumentParser(
        description="Run Elastic Logs analysis via Devin API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_analysis.py logs/sample_01_normal_traffic.json
  python run_analysis.py logs/elastic_logs.json --playbook-id YOUR_PLAYBOOK_ID

Prerequisites:
  1. Set DEVIN_API_KEY environment variable
  2. Install requests: pip install requests
        """,
    )
    parser.add_argument(
        "log_file",
        help="Path to the log file to analyze (e.g., logs/sample_01_normal_traffic.json)",
    )
    parser.add_argument(
        "--playbook-id",
        help="Optional Devin playbook ID for structured analysis",
        default=None,
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to save analysis results",
        default="analysis",
    )

    args = parser.parse_args()

    # Check for API key
    api_key = os.environ.get("DEVIN_API_KEY")
    if not api_key:
        print("Error: DEVIN_API_KEY environment variable is not set.")
        print()
        print("To set it, run:")
        print('  export DEVIN_API_KEY="your-api-key-here"')
        print()
        print("You can get your API key from: https://app.devin.ai/settings/api")
        sys.exit(1)

    # Load and validate log file
    print(f"Loading log file: {args.log_file}")
    try:
        logs = load_log_file(args.log_file)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print()
        print("Available log files:")
        if os.path.exists("logs"):
            for f in sorted(os.listdir("logs")):
                if f.endswith(".json"):
                    print(f"  logs/{f}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in log file: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Loaded {len(logs)} log entries")

    # Generate analysis prompt
    prompt = generate_analysis_prompt(args.log_file, logs)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Initialize API client and create session
    print()
    print("Creating Devin session for analysis...")
    client = DevinAPIClient(api_key)

    try:
        result = client.create_session(prompt, args.playbook_id)
    except requests.exceptions.HTTPError as e:
        print(f"Error: API request failed: {e}")
        if e.response is not None:
            print(f"Response: {e.response.text}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error: Network error: {e}")
        sys.exit(1)

    # Display results
    session_id = result.get("session_id", "unknown")
    session_url = result.get("url", "")

    print()
    print("=" * 60)
    print("Analysis Session Created Successfully!")
    print("=" * 60)
    print()
    print(f"Session ID: {session_id}")
    print(f"Session URL: {session_url}")
    print()
    print("The analysis is now running in the background.")
    print("Visit the session URL above to monitor progress and view results.")
    print()

    # Save session info
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    session_file = os.path.join(args.output_dir, f"session_{timestamp}.json")
    session_info = {
        "session_id": session_id,
        "session_url": session_url,
        "log_file": args.log_file,
        "playbook_id": args.playbook_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    with open(session_file, "w") as f:
        json.dump(session_info, f, indent=2)

    print(f"Session info saved to: {session_file}")


if __name__ == "__main__":
    main()
