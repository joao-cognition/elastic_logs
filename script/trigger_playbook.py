#!/usr/bin/env python3
"""Trigger the Elastic Logs Analysis playbook using Devin's API."""

import json
import os
import sys
from datetime import datetime
from typing import Any

import requests


def load_playbook(playbook_path: str) -> dict[str, Any]:
    """Load playbook configuration from YAML file.

    Args:
        playbook_path: Path to the playbook YAML file.

    Returns:
        Playbook configuration dictionary.
    """
    import yaml

    with open(playbook_path, "r") as f:
        return yaml.safe_load(f)


def create_playbook_prompt(
    playbook: dict[str, Any], log_file: str, output_dir: str
) -> str:
    """Create a comprehensive prompt from the playbook.

    Args:
        playbook: Playbook configuration.
        log_file: Path to the log file.
        output_dir: Directory for output files.

    Returns:
        Combined prompt string for all tasks.
    """
    tasks = playbook.get("tasks", [])
    task_prompts = []

    for task in tasks:
        task_name = task.get("name", "unknown")
        task_desc = task.get("description", "")
        task_prompt = task.get("prompt", "")

        # Replace template variables
        task_prompt = task_prompt.replace("{{ log_file }}", log_file)
        task_prompt = task_prompt.replace("{{ output_dir }}", output_dir)

        task_prompts.append(f"## Task: {task_name}\n{task_desc}\n\n{task_prompt}")

    combined_prompt = f"""Execute the Elastic Logs Analysis Playbook.

{playbook.get("description", "")}

The following tasks should be performed in sequence:

{"".join(task_prompts)}

After completing all tasks, provide a summary of findings from each analysis."""

    return combined_prompt


def call_devin_api(prompt: str, api_key: str) -> dict[str, Any]:
    """Call Devin's API to create a session with the playbook prompt.

    Args:
        prompt: The playbook prompt.
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


def save_playbook_result(
    result: dict[str, Any], playbook_name: str, output_dir: str
) -> str:
    """Save playbook execution result to a file.

    Args:
        result: API response data.
        playbook_name: Name of the playbook.
        output_dir: Directory to save the result.

    Returns:
        Path to the saved file.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"playbook_execution_{timestamp}.json")

    execution_data = {
        "playbook_name": playbook_name,
        "timestamp": datetime.now().isoformat(),
        "devin_session": result,
    }

    with open(output_file, "w") as f:
        json.dump(execution_data, f, indent=2)

    return output_file


def main() -> int:
    """Main function to trigger the playbook.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    api_key = os.environ.get("DEVIN_API_KEY")
    if not api_key:
        print("Error: DEVIN_API_KEY environment variable not set")
        return 1

    playbook_path = (
        sys.argv[1] if len(sys.argv) > 1 else "playbook/elastic_logs_analysis.yaml"
    )
    log_file = sys.argv[2] if len(sys.argv) > 2 else "logs/elastic_logs.json"
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "analysis"

    print(f"Loading playbook from {playbook_path}...")

    try:
        playbook = load_playbook(playbook_path)
    except ImportError:
        print("PyYAML not installed. Installing...")
        os.system("pip install pyyaml")
        import yaml

        with open(playbook_path, "r") as f:
            playbook = yaml.safe_load(f)

    playbook_name = playbook.get("name", "Unknown Playbook")
    print(f"Playbook: {playbook_name}")

    print("Creating playbook prompt...")
    prompt = create_playbook_prompt(playbook, log_file, output_dir)

    print("Triggering playbook via Devin API...")
    result = call_devin_api(prompt, api_key)

    print("Saving execution result...")
    output_file = save_playbook_result(result, playbook_name, output_dir)
    print(f"Execution result saved to {output_file}")

    session_url = result.get("url", "N/A")
    print(f"\nDevin session URL: {session_url}")
    print("The playbook is now being executed by Devin.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
