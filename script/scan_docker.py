#!/usr/bin/env python3
"""
Docker Code Scanning Script.

This script uses Devin's API to scan Docker code for security vulnerabilities,
misconfigurations, and best practice violations.
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from devin_api import DevinAPIClient


def build_docker_scan_prompt(docker_dir: str, files: list[str]) -> str:
    """
    Build the prompt for Docker code scanning.

    Args:
        docker_dir: Path to the directory containing Docker files.
        files: List of Docker-related files found.

    Returns:
        The scanning prompt string.
    """
    files_list = "\n".join(f"- {f}" for f in files)
    
    return f"""Perform a comprehensive security and best practices scan of the Docker code in the repository.

**Directory to scan:** `{docker_dir}`

**Files to analyze:**
{files_list}

Please perform the following analyses:

## 1. Dockerfile Security Analysis
For each Dockerfile, check for:
- **Base Image Issues**: Using `latest` tag, deprecated images, or images with known vulnerabilities
- **Privilege Escalation**: Running as root, missing USER directive
- **Secrets Exposure**: Hardcoded credentials, API keys, or sensitive data in ENV or ARG
- **Unnecessary Packages**: Installing packages not needed for the application
- **File Permissions**: Overly permissive chmod commands
- **Build Optimization**: Missing multi-stage builds, inefficient layer caching

## 2. Docker Compose Security Analysis
For docker-compose files, check for:
- **Privileged Containers**: Containers running with elevated privileges
- **Volume Mounts**: Sensitive host directories mounted into containers
- **Network Exposure**: Unnecessary port exposures, missing network isolation
- **Secrets Management**: Hardcoded secrets in environment variables
- **Resource Limits**: Missing CPU/memory limits
- **Health Checks**: Missing or inadequate health checks

## 3. Application Code Security (if present)
For any application code in the Docker context:
- **SQL Injection**: Vulnerable database queries
- **Command Injection**: Unsafe command execution
- **Path Traversal**: Unsafe file path handling
- **Authentication Issues**: Weak authentication mechanisms
- **Sensitive Data Exposure**: Debug endpoints, exposed credentials

## 4. Best Practices Compliance
Check compliance with Docker best practices:
- Using specific image tags
- Minimizing image layers
- Using .dockerignore
- Non-root user execution
- Health check implementation
- Proper signal handling

## Output Requirements
Please provide a detailed report with:

1. **Executive Summary**: Overall security posture and risk level
2. **Critical Findings**: Issues that must be fixed immediately
3. **High Priority Findings**: Significant security concerns
4. **Medium Priority Findings**: Best practice violations
5. **Low Priority Findings**: Minor improvements
6. **Remediation Guide**: Step-by-step fixes for each finding
7. **Secure Dockerfile Examples**: Corrected versions of problematic Dockerfiles

Save your analysis report to `analysis/docker_scan_report.md`"""


def find_docker_files(docker_dir: str) -> list[str]:
    """
    Find all Docker-related files in the specified directory.

    Args:
        docker_dir: Path to the directory to scan.

    Returns:
        List of Docker-related file paths.
    """
    docker_files = []
    docker_patterns = [
        "Dockerfile*",
        "docker-compose*.yml",
        "docker-compose*.yaml",
        ".dockerignore",
        "*.dockerfile",
    ]
    
    path = Path(docker_dir)
    if not path.exists():
        return docker_files
    
    for pattern in docker_patterns:
        docker_files.extend([str(f.relative_to(path)) for f in path.glob(pattern)])
        docker_files.extend([str(f.relative_to(path)) for f in path.glob(f"**/{pattern}")])
    
    for ext in [".py", ".js", ".sh", ".sql"]:
        docker_files.extend([str(f.relative_to(path)) for f in path.glob(f"*{ext}")])
        docker_files.extend([str(f.relative_to(path)) for f in path.glob(f"**/*{ext}")])
    
    return sorted(set(docker_files))


def main() -> None:
    """Run Docker code scanning using Devin API."""
    parser = argparse.ArgumentParser(
        description="Scan Docker code for security issues using Devin API"
    )
    parser.add_argument(
        "--docker-dir",
        default="docker_code",
        help="Path to the directory containing Docker files",
    )
    parser.add_argument(
        "--output-dir",
        default="analysis",
        help="Directory to save scan results",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for scan to complete",
    )
    args = parser.parse_args()

    if not os.path.exists(args.docker_dir):
        print(f"Error: Docker directory not found: {args.docker_dir}")
        sys.exit(1)

    docker_files = find_docker_files(args.docker_dir)
    if not docker_files:
        print(f"Warning: No Docker files found in {args.docker_dir}")
        print("Proceeding with general directory scan...")
        docker_files = ["(directory scan)"]

    print(f"Found {len(docker_files)} Docker-related files:")
    for f in docker_files[:10]:
        print(f"  - {f}")
    if len(docker_files) > 10:
        print(f"  ... and {len(docker_files) - 10} more")

    print("\nInitializing Devin API client...")
    try:
        client = DevinAPIClient()
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    prompt = build_docker_scan_prompt(args.docker_dir, docker_files)

    print("Creating Devin session for Docker code scanning...")
    try:
        session = client.create_session(
            prompt=prompt,
            idempotency_key=f"docker-scan-{datetime.utcnow().strftime('%Y%m%d')}",
        )
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
        "scan_type": "docker",
        "docker_dir": args.docker_dir,
        "files_scanned": docker_files,
        "session_id": session_id,
        "session_url": session_url,
        "status": "initiated",
    }

    result_file = f"{args.output_dir}/docker_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(result_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"  Result saved to: {result_file}")

    if args.wait:
        print("\nWaiting for scan to complete...")
        try:
            final_status = client.wait_for_completion(session_id)
            print(f"Scan completed with status: {final_status.get('status_enum')}")

            result["status"] = final_status.get("status_enum")
            result["final_response"] = final_status
            with open(result_file, "w") as f:
                json.dump(result, f, indent=2)

        except TimeoutError as e:
            print(f"Warning: {e}")

    print("\nDocker code scanning initiated successfully!")
    print(f"Monitor progress at: {session_url}")


if __name__ == "__main__":
    main()
