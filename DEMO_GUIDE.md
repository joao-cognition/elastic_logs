# Elastic Logs Analysis Demo Guide

This guide provides comprehensive instructions for running the Elastic Logs analysis demonstration using Devin's API and GitHub Actions. The demo includes two main use cases: Elastic Log analysis and Docker code scanning.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Repository Structure](#repository-structure)
4. [Setup Instructions](#setup-instructions)
5. [Use Case 1: Elastic Log Analysis](#use-case-1-elastic-log-analysis)
6. [Use Case 2: Docker Code Scanning](#use-case-2-docker-code-scanning)
7. [GitHub Actions Integration](#github-actions-integration)
8. [Playbook Usage](#playbook-usage)
9. [Troubleshooting](#troubleshooting)

## Overview

This demonstration showcases how to integrate Devin's API with GitHub Actions to automate code and log analysis. The repository contains sample Elastic Logs with various issues (errors, security threats, performance anomalies) and Docker code with security vulnerabilities that Devin can analyze.

### Key Features

The demo includes three types of log analysis (error pattern detection, security issue identification, and performance anomaly detection), Docker code security scanning, GitHub Actions workflows for automated analysis, and a playbook-based approach for flexible analysis configuration.

## Prerequisites

Before running the demo, ensure you have Python 3.11 or higher installed, a Devin API key (obtain from your Devin account), Git installed and configured, and access to the GitHub repository.

### Required Python Packages

Install the required packages using pip:

```bash
pip install requests
```

## Repository Structure

```
elastic_logs/
├── logs/                           # Generated Elastic Logs
│   └── elastic_logs.json          # 100 sample log entries
├── script/                         # API scripts
│   ├── devin_api.py               # Devin API client module
│   ├── generate_logs.py           # Log generation script
│   ├── analyze_errors.py          # Error pattern analysis
│   ├── analyze_security.py        # Security issue detection
│   ├── analyze_performance.py     # Performance anomaly analysis
│   ├── run_all_analyses.py        # Unified analysis script
│   ├── run_playbook.py            # Playbook execution script
│   └── scan_docker.py             # Docker code scanning
├── docker_code/                    # Sample Docker code with issues
│   ├── Dockerfile.api             # API service Dockerfile
│   ├── Dockerfile.web             # Web frontend Dockerfile
│   ├── Dockerfile.database        # Database Dockerfile
│   ├── docker-compose.yml         # Docker Compose configuration
│   ├── app.py                     # Sample application code
│   └── init-scripts/              # Database init scripts
├── analysis/                       # Analysis results (generated)
├── .github/workflows/              # GitHub Actions
│   ├── analyze-logs.yml           # Individual analysis workflow
│   ├── analyze-logs-playbook.yml  # Playbook-based workflow
│   └── scan-docker.yml            # Docker scanning workflow
├── playbook.yaml                   # Analysis playbook definition
└── DEMO_GUIDE.md                  # This guide
```

## Setup Instructions

### Step 1: Clone the Repository

```bash
git clone https://github.com/joao-cognition/elastic_logs.git
cd elastic_logs
```

### Step 2: Set Up Environment Variables

Export your Devin API key:

```bash
export DEVIN_API_KEY="your-api-key-here"
```

For GitHub Actions, add the `DEVIN_API_KEY` as a repository secret by navigating to Settings > Secrets and variables > Actions > New repository secret.

### Step 3: Generate Sample Logs (Optional)

The repository includes pre-generated logs, but you can regenerate them:

```bash
python script/generate_logs.py
```

This creates 100 log entries with a mix of normal logs (60%), error logs (15%), security-related logs (15%), and performance anomaly logs (10%).

## Use Case 1: Elastic Log Analysis

### Running Individual Analyses

You can run each analysis type separately using the individual scripts.

**Error Pattern Analysis** identifies 500 errors, timeouts, connection failures, and error cascades:

```bash
python script/analyze_errors.py --log-file logs/elastic_logs.json
```

**Security Issue Detection** finds failed authentication attempts, SQL injection attempts, suspicious IPs, and rate limit violations:

```bash
python script/analyze_security.py --log-file logs/elastic_logs.json
```

**Performance Anomaly Analysis** detects slow response times, high memory usage, database performance issues, and resource exhaustion:

```bash
python script/analyze_performance.py --log-file logs/elastic_logs.json
```

### Running All Analyses Together

Use the unified script to run all three analyses:

```bash
python script/run_all_analyses.py --log-file logs/elastic_logs.json
```

You can also specify which analyses to run:

```bash
python script/run_all_analyses.py --analyses error security
```

### Understanding the Results

Each analysis creates a JSON file in the `analysis/` folder containing the session ID and URL for tracking, the prompt used for analysis, the timestamp of when the analysis was initiated, and the current status.

Visit the session URL to view detailed analysis results in Devin's interface.

## Use Case 2: Docker Code Scanning

### Sample Docker Code Issues

The `docker_code/` directory contains intentionally vulnerable Docker configurations for demonstration purposes.

**Dockerfile Issues** include using `latest` tags instead of specific versions, running containers as root, hardcoded secrets in environment variables, installing unnecessary packages, and overly permissive file permissions.

**Docker Compose Issues** include privileged container mode, mounting sensitive host directories (like Docker socket), exposing unnecessary ports, missing resource limits, and no health checks defined.

**Application Code Issues** include SQL injection vulnerabilities, command injection vulnerabilities, path traversal vulnerabilities, hardcoded credentials, and debug endpoints exposing sensitive data.

### Running Docker Code Scan

```bash
python script/scan_docker.py --docker-dir docker_code
```

The scan analyzes all Dockerfiles, docker-compose files, and application code in the specified directory.

### Scan Output

The scan produces a detailed report covering Dockerfile security analysis, Docker Compose security analysis, application code security review, and best practices compliance check.

## GitHub Actions Integration

### Available Workflows

**analyze-logs.yml** triggers on push to `logs/` folder and runs all three log analyses individually.

**analyze-logs-playbook.yml** triggers on push to `logs/` folder and uses the playbook for unified analysis.

**scan-docker.yml** triggers on push to `docker_code/` folder and scans Docker code for security issues.

### Triggering Workflows Manually

All workflows support manual triggering via `workflow_dispatch`. Go to the Actions tab in GitHub, select the workflow, and click "Run workflow".

### Workflow Inputs

**Log Analysis Workflows** accept `log_file` (path to log file, default: `logs/elastic_logs.json`).

**Docker Scan Workflow** accepts `docker_dir` (path to Docker code, default: `docker_code`).

### Viewing Results

Workflow results are available in the GitHub Actions run summary, as downloadable artifacts (retained for 30 days), and in the Devin session (URL provided in logs).

## Playbook Usage

### Understanding the Playbook

The `playbook.yaml` file defines a reusable analysis configuration that encapsulates all three log analysis tasks, can be updated without modifying GitHub Actions, and supports input parameters for flexibility.

### Playbook Structure

```yaml
name: Elastic Logs Analysis Playbook
inputs:
  log_file: logs/elastic_logs.json
  output_dir: analysis
tasks:
  - error_pattern_analysis
  - security_issue_detection
  - performance_anomaly_analysis
```

### Running the Playbook

```bash
python script/run_playbook.py --log-file logs/elastic_logs.json
```

With a specific playbook ID (if registered with Devin):

```bash
python script/run_playbook.py --playbook-id your-playbook-id
```

### Benefits of Playbook Approach

Using playbooks provides centralized configuration where all analysis tasks are defined in one place, flexibility to update analysis logic without changing workflows, consistency ensuring the same analysis is run every time, and version control to track changes to analysis configuration.

## Troubleshooting

### Common Issues

**"DEVIN_API_KEY not set"** means you need to export the environment variable:
```bash
export DEVIN_API_KEY="your-api-key"
```

**"Log file not found"** means you should verify the path exists:
```bash
ls -la logs/
```

**"Session creation failed"** means you should check your API key is valid and you have API access.

### GitHub Actions Issues

**Workflow not triggering** - Verify the file path matches the trigger pattern and check that the workflow file is valid YAML.

**Secret not available** - Ensure `DEVIN_API_KEY` is added as a repository secret and the secret name matches exactly.

### Getting Help

For issues with Devin's API, consult the Devin API documentation. For repository-specific issues, open an issue in the GitHub repository. For general questions, contact the repository maintainers.

## Next Steps

After running the demo, consider customizing the log generation to match your actual log format, modifying the analysis prompts for your specific use cases, integrating with your CI/CD pipeline, and setting up alerts based on analysis results.

## License

This demonstration code is provided as-is for educational purposes.
