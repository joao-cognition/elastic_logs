#!/usr/bin/env python3
"""Trigger 3 parallel Devin sessions to analyze a log file."""

import argparse
import os
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json


class DevinAPIClient:
    """Client for interacting with Devin's API."""
    
    BASE_URL = "https://api.devin.ai/v1"
    
    def __init__(self):
        self.api_key = os.environ.get("DEVIN_API_KEY")
        if not self.api_key:
            raise ValueError("DEVIN_API_KEY environment variable is required")
    
    def create_session(self, prompt: str):
        """Create a new Devin session."""
        payload = {"prompt": prompt}
        
        data = json.dumps(payload).encode('utf-8')
        request = Request(
            f"{self.BASE_URL}/sessions",
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST"
        )
        
        try:
            with urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode('utf-8'))
        except HTTPError as e:
            error_body = e.read().decode('utf-8')
            raise Exception(f"HTTP {e.code}: {error_body}")
        except URLError as e:
            raise Exception(f"Connection error: {e.reason}")


def main():
    parser = argparse.ArgumentParser(description="Analyze log file with Devin")
    parser.add_argument("log_file", help="Path to log file")
    args = parser.parse_args()
    
    if not os.path.exists(args.log_file):
        print(f"Error: {args.log_file} not found")
        return
    
    client = DevinAPIClient()
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    
    # Three simple analysis prompts
    prompts = {
        "error": f"Read {args.log_file}. Count all entries with level='ERROR'. Group by: status_code, service_name, error_message. List top 10 most frequent errors. Save as error_report_{timestamp}.html in analysis/",
        
        "performance": f"Read {args.log_file}. Calculate response_time stats: min, max, avg, p95, p99. List slowest 10 endpoints. Identify any response_time > 1000ms. Save as performance_report_{timestamp}.html in analysis/",
        
        "security": f"Read {args.log_file}. Find: status_code=401/403 entries, unique IPs with >10 failed requests, any SQL/XSS patterns in request_path. Save as security_report_{timestamp}.html in analysis/"
    }
    
    # Trigger all 3 sessions
    for name, prompt in prompts.items():
        print(f"Starting {name} analysis...")
        session = client.create_session(prompt=prompt)
        print(f"  → {session['url']}")
    
    print(f"\n✓ 3 sessions started. HTML reports will be saved to analysis/")


if __name__ == "__main__":
    main()