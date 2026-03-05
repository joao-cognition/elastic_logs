# Elastic Logs Analysis Demo Guide

This guide demonstrates how to automate log analysis with Devin. The demo walks through setting up API keys, running analysis from the IDE, automating analysis with GitHub Actions, and creating playbooks for repeatable workflows.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Demo Steps](#demo-steps)
   - [Step 1: API Key Generation](#step-1-api-key-generation)
   - [Step 2: GitHub Secrets Configuration](#step-2-github-secrets-configuration)
   - [Step 3: IDE Analysis](#step-3-ide-analysis)
   - [Step 4: Log Analysis Script](#step-4-log-analysis-script)
   - [Step 5: Automate Analysis on New Files](#step-5-automate-analysis-on-new-files)
   - [Step 6: Add New Log (First Instance)](#step-6-add-new-log-first-instance)
   - [Step 7: Playbook Creation](#step-7-playbook-creation)
   - [Step 8: GitHub Action for Playbook](#step-8-github-action-for-playbook)
   - [Step 9: Add New Log (Second Instance)](#step-9-add-new-log-second-instance)
4. [Repository Structure](#repository-structure)
5. [Troubleshooting](#troubleshooting)

## Overview

This demonstration showcases how Devin can be automatically triggered to run analysis on new code and log files. The workflow includes generating API keys, configuring GitHub secrets, running analysis from the IDE, and setting up automated GitHub Actions that trigger Devin to analyze logs whenever new files are added to the repository.

### Key Features

The demo covers API key generation and management, GitHub Secrets configuration for secure credential storage, IDE-based log analysis sessions, automated log analysis using Python scripts, GitHub Actions for continuous analysis on new file additions, and playbook-based workflows for consistent, repeatable analysis.

## Prerequisites

Before running the demo, ensure you have access to a Devin account with API capabilities, a GitHub repository with write access, Python 3.11 or higher installed locally, and Git installed and configured.

## Demo Steps

### Step 1: API Key Generation

Generate a Devin API Key to enable programmatic access to Devin's analysis capabilities.

1. Navigate to your Devin account settings
2. Go to the API section
3. Click "Generate New API Key"
4. Copy the generated API key and store it securely

The API key will be used in subsequent steps to authenticate requests to Devin's API for log analysis.

### Step 3: IDE Analysis

Run analysis sessions directly from your IDE to analyze a specific log file.

1. Open the repository in your IDE (VS Code, IntelliJ, etc.)
2. Navigate to the `logs/` directory
3. Open the file `logs/elastic_logs_28_11_25.json`
4. Use Devin's IDE integration to trigger analysis on this file
5. Devin will analyze the log file for errors, security issues, and performance anomalies

The analysis will identify error patterns, security threats, and performance bottlenecks in the log data.

### Step 4: Log Analysis Script

Run the log analysis script to trigger Devin sessions for comprehensive log analysis.

```bash
export DEVIN_API_KEY='apk_user_Z29vZ2xlLW9hdXRoMnwxMTAxOTc0MzU5NDQ0ODU2MDMzNDVfb3JnLWE1YTc4MGU4YzcwMDQyNjliN2NhZmMyYzVhNzdhMDM5OjY5YTNmZjViZTFjNTQyMGE4MTA3NGM4MGY4MWNiMGMw'
```

```bash
python3 script/analyze_logs.py logs/elastic_logs_28_11_25.json
```

This script (`script/analyze_logs.py`) triggers three parallel Devin sessions:

1. **Error Analysis**: Counts ERROR level entries, groups by status code/service/message, lists top 10 frequent errors
2. **Performance Analysis**: Calculates response time statistics (min, max, avg, p95, p99), identifies slow endpoints
3. **Security Analysis**: Finds 401/403 entries, identifies suspicious IPs, detects SQL/XSS patterns

The script saves session information to the `analysis/` directory and provides URLs to track each analysis session.

### Step 5: Automate Analysis on New Files

# GitHub Secrets Configuration

Add the generated API Key to GitHub Secrets to enable secure access from GitHub Actions.

1. Navigate to your GitHub repository (joao-cognition/elastic_logs)
2. Go to **Settings** > **Secrets and variables** > **Actions**
3. Click **New repository secret**
4. Name the secret `DEVIN_API_KEY`
5. Paste your API key as the value
6. Click **Add secret**

This secret will be available to GitHub Actions workflows for authenticating with Devin's API.

Set up a GitHub Action to automatically run log analysis whenever a new file is added to the `logs/` directory.

The GitHub Actions workflow is defined in `.github/workflows/analyze-logs.yml`. It triggers automatically on pushes to `logs/**` and also supports manual execution via `workflow_dispatch` with configurable inputs for `log_file` and `analysis_type`.

The workflow includes the following jobs:

1. **detect-changes** - Identifies new or modified JSON log files
2. **validate** - Verifies log files exist and contain valid JSON arrays
3. **lint** - Runs flake8 on Python scripts
4. **test** - Runs pytest with coverage (if a `tests/` directory exists)
5. **analyze** - Runs error, performance, and security analysis in parallel via Devin API
6. **archive-reports** - Uploads generated HTML reports as workflow artifacts
7. **notify** - Reports final pipeline status

This workflow automatically triggers Devin to analyze any new log files added to the repository.

### Step 6: Add New Log (First Instance)

Add a new log file to demonstrate the automated analysis workflow.

1. Move the log file `elastic_logs_29_11_25.json` from the `logs_to_be/` folder to the `logs/` folder
2. Commit and push the changes:

```bash
mv logs_to_be/elastic_logs_29_11_25.json logs/
git add logs/elastic_logs_29_11_25.json
git commit -m "feat: add elastic logs for November 29, 2025"
git push origin main
```

3. Create a Pull Request to trigger the GitHub Action
4. Observe the GitHub Action running and creating an issue for Devin to analyze the new log file

### Step 7: Playbook Creation

Create a playbook that encapsulates all the analysis steps performed so far. The playbook is saved at `playbook/PLAYBOOK.md`.

The playbook defines a reusable analysis configuration that includes:

1. **Error Pattern Analysis**: Analyzes logs for error patterns, frequency, root causes, and impact assessment
2. **Security Issue Detection**: Detects authentication issues, suspicious IPs, injection attacks, and access control violations
3. **Performance Anomaly Analysis**: Identifies response time issues, resource utilization problems, and capacity planning insights

The playbook can be executed via Devin's API or manually using the individual analysis scripts:

```bash
# Run the playbook
python script/run_playbook.py --log-file logs/elastic_logs_28_11_25.json --output-dir analysis
```

See `playbook/PLAYBOOK.md` for the complete playbook definition and execution instructions.

### Step 8: GitHub Action for Playbook

A separate GitHub Actions workflow triggers the Devin playbook for automated analysis. The workflow is defined in `.github/workflows/analyze-logs-playbook.yml`.

It triggers on pushes to `logs/**`, detects changed JSON files using `tj-actions/changed-files`, and calls the Devin API with a playbook prompt for each file. Retry logic with exponential backoff is included for resilience.

This workflow triggers the Devin playbook whenever new log files are added, providing a consistent and automated analysis process.

### Step 9: Add New Log (Second Instance)

Add another log file to verify the playbook-based automation is working correctly.

1. Move the log file `elastic_logs_30_11_25.json` from the `logs_to_be/` folder to the `logs/` folder
2. Commit and push the changes:

```bash
mv logs_to_be/elastic_logs_30_11_25.json logs/
git add logs/elastic_logs_30_11_25.json
git commit -m "feat: add elastic logs for November 30, 2025"
git push origin main
```

3. Create a Pull Request
4. Observe both GitHub Actions (analyze-logs-on-new-file and analyze-logs-playbook) triggering
5. Verify that Devin receives the analysis request and begins processing

## Repository Structure

```
elastic_logs/
├── logs/                                    # Log files for analysis
│   └── elastic_logs_28_11_25.json          # Sample logs (November 28, 2025)
├── logs_to_be/                              # Staging folder for new log files
│   ├── elastic_logs_29_11_25.json          # Sample logs (November 29, 2025)
│   └── elastic_logs_30_11_25.json          # Sample logs (November 30, 2025)
├── script/                                  # Analysis scripts
│   └── analyze_logs.py                     # Main log analysis script
├── playbook/                                # Playbook definitions
│   └── PLAYBOOK.md                         # Log analysis playbook
├── .github/workflows/                       # GitHub Actions workflows
│   ├── analyze-logs.yml                    # Main analysis workflow (trigger on new log files)
│   └── analyze-logs-playbook.yml           # Playbook-based analysis workflow
├── analysis/                                # Generated analysis reports
└── DEMO_GUIDE.md                           # This guide
```

## Troubleshooting

### API Key Issues

If you encounter "DEVIN_API_KEY not set" errors, ensure the environment variable is exported locally or the GitHub secret is properly configured. Verify the API key is valid and has not expired.

### GitHub Action Not Triggering

If the GitHub Action does not trigger when adding new log files, verify the file path matches the trigger pattern (`logs/**`), check that the workflow file is valid YAML, and ensure the workflow is enabled in the repository settings.

### Analysis Session Failures

If analysis sessions fail to create, check your API key permissions, verify network connectivity to api.devin.ai, and review the error message for specific issues.

### Log File Format Issues

Ensure log files are valid JSON format. The analysis scripts expect log entries with specific fields including `@timestamp`, `level`, `service`, `http`, and `client` objects.

## Next Steps

After completing the demo, consider customizing the analysis prompts for your specific use cases, adding additional log sources and formats, integrating analysis results with alerting systems, and expanding the playbook with additional analysis tasks.
