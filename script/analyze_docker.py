#!/usr/bin/env python3
"""Analyze Dockerfiles for issues using Devin's API."""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import requests


def load_dockerfile(dockerfile_path: str) -> str:
    """Load Dockerfile content from a file.

    Args:
        dockerfile_path: Path to the Dockerfile.

    Returns:
        Dockerfile content as string.
    """
    with open(dockerfile_path, "r") as f:
        return f.read()


def create_analysis_prompt(dockerfile_content: str, dockerfile_path: str) -> str:
    """Create a prompt for Devin to analyze the Dockerfile.

    Args:
        dockerfile_content: Content of the Dockerfile.
        dockerfile_path: Path to the Dockerfile for context.

    Returns:
        Analysis prompt string.
    """
    return f"""Analyze the following Dockerfile for issues, security vulnerabilities, and best practice violations.

Dockerfile path: {dockerfile_path}

Dockerfile content:
```dockerfile
{dockerfile_content}
```

Please identify and categorize issues in the following areas:

1. **Security Issues**
   - Hardcoded secrets or credentials
   - Running as root user
   - Exposed sensitive ports
   - Insecure base images

2. **Best Practice Violations**
   - Using 'latest' tag instead of specific versions
   - Not combining RUN commands
   - Using ADD instead of COPY for local files
   - Not cleaning up package manager caches
   - Missing health checks
   - Using shell form instead of exec form for CMD/ENTRYPOINT

3. **Performance Issues**
   - Large base images
   - Inefficient layer caching
   - Unnecessary packages installed

4. **Maintainability Issues**
   - Missing labels and metadata
   - Poor documentation
   - Missing .dockerignore considerations

For each issue found, provide:
- Issue description
- Severity (Critical, High, Medium, Low)
- Location in the Dockerfile
- Recommended fix

Provide a summary with the total count of issues by severity."""


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


def find_dockerfiles(search_path: str) -> list[str]:
    """Find all Dockerfiles in the given path.

    Args:
        search_path: Directory path to search for Dockerfiles.

    Returns:
        List of Dockerfile paths.
    """
    dockerfiles = []
    path = Path(search_path)

    if path.is_file():
        return [str(path)]

    for dockerfile in path.rglob("Dockerfile*"):
        if dockerfile.is_file():
            dockerfiles.append(str(dockerfile))

    return dockerfiles


def save_analysis_result(
    result: dict[str, Any],
    dockerfile_path: str,
    dockerfile_content: str,
    output_dir: str,
) -> str:
    """Save analysis result to a file.

    Args:
        result: API response data.
        dockerfile_path: Path to the analyzed Dockerfile.
        dockerfile_content: Content of the Dockerfile.
        output_dir: Directory to save the result.

    Returns:
        Path to the saved file.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dockerfile_name = Path(dockerfile_path).name.replace(".", "_")
    output_file = os.path.join(
        output_dir, f"docker_analysis_{dockerfile_name}_{timestamp}.json"
    )

    analysis_data = {
        "analysis_type": "docker_scan",
        "timestamp": datetime.now().isoformat(),
        "dockerfile_path": dockerfile_path,
        "dockerfile_content": dockerfile_content,
        "devin_session": result,
    }

    with open(output_file, "w") as f:
        json.dump(analysis_data, f, indent=2)

    return output_file


def main() -> int:
    """Main function to run Docker analysis.

    Returns:
        Exit code (0 for success, 1 for failure).
    """
    api_key = os.environ.get("DEVIN_API_KEY")
    if not api_key:
        print("Error: DEVIN_API_KEY environment variable not set")
        return 1

    dockerfile_path = sys.argv[1] if len(sys.argv) > 1 else "docker/Dockerfile"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "analysis"

    print(f"Searching for Dockerfiles in {dockerfile_path}...")
    dockerfiles = find_dockerfiles(dockerfile_path)

    if not dockerfiles:
        print(f"No Dockerfiles found in {dockerfile_path}")
        return 0

    print(f"Found {len(dockerfiles)} Dockerfile(s)")

    results = []
    for dockerfile in dockerfiles:
        print(f"\nAnalyzing {dockerfile}...")

        dockerfile_content = load_dockerfile(dockerfile)
        print(f"Dockerfile size: {len(dockerfile_content)} characters")

        print("Creating analysis prompt...")
        prompt = create_analysis_prompt(dockerfile_content, dockerfile)

        print("Calling Devin API for Docker analysis...")
        result = call_devin_api(prompt, api_key)

        print("Saving analysis result...")
        output_file = save_analysis_result(
            result, dockerfile, dockerfile_content, output_dir
        )
        print(f"Analysis saved to {output_file}")

        session_url = result.get("url", "N/A")
        print(f"Devin session URL: {session_url}")

        results.append(
            {
                "dockerfile": dockerfile,
                "output_file": output_file,
                "session_url": session_url,
            }
        )

    print("\n=== Summary ===")
    for r in results:
        print(f"Dockerfile: {r['dockerfile']}")
        print(f"  Result: {r['output_file']}")
        print(f"  Session: {r['session_url']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
