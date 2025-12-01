# Elastic Logs Analysis Demonstration Guidebook

This guidebook provides comprehensive instructions for running the Elastic Logs analysis demonstration using Devin's API and GitHub Actions.

## Overview

This demonstration showcases how to analyze Elastic Logs for various issues using Devin's AI-powered analysis capabilities. The system performs three types of analysis on log data: application error detection, security threat identification, and performance issue analysis.

## Prerequisites

Before running this demonstration, ensure you have the following:

1. Python 3.11 or higher installed on your system
2. A Devin API key (obtain from your Devin account)
3. Git installed for repository management
4. Access to the GitHub repository with appropriate permissions

## Repository Structure

The repository is organized as follows:

```
elastic_logs/
├── logs/                          # Generated Elastic Log files
│   └── elastic_logs.json          # Sample log file with 100 entries
├── script/                        # Analysis scripts
│   ├── generate_logs.py           # Log generation script
│   ├── analyze_errors.py          # Error analysis script
│   ├── analyze_security.py        # Security analysis script
│   ├── analyze_performance.py     # Performance analysis script
│   ├── run_all_analyses.py        # Combined analysis script
│   └── trigger_playbook.py        # Playbook trigger script
├── playbook/                      # Playbook definitions
│   └── elastic_logs_analysis.yaml # Main analysis playbook
├── analysis/                      # Analysis results (generated)
├── .github/workflows/             # GitHub Actions workflows
│   ├── analyze_logs.yml           # Individual analysis workflow
│   └── analyze_logs_playbook.yml  # Playbook-based workflow
└── GUIDEBOOK.md                   # This file
```

## Setting Up the Environment

### Step 1: Clone the Repository

```bash
git clone https://github.com/joao-cognition/elastic_logs.git
cd elastic_logs
```

### Step 2: Set Up the Devin API Key

Export your Devin API key as an environment variable:

```bash
export DEVIN_API_KEY="your-api-key-here"
```

For GitHub Actions, add the API key as a repository secret named `DEVIN_API_KEY`.

### Step 3: Install Python Dependencies

```bash
pip install requests pyyaml
```

## Generating Sample Logs

The repository includes a script to generate 100 sample Elastic Log entries with various issues. To generate new logs:

```bash
python script/generate_logs.py
```

This creates `logs/elastic_logs.json` with the following distribution:
- Approximately 60% normal INFO level logs
- Approximately 15% ERROR level logs (application errors)
- Approximately 15% WARN level logs (security issues)
- Approximately 10% WARN level logs (performance issues)

## Running Individual Analyses

### Error Analysis

Analyzes application errors including database timeouts, connection failures, and exceptions:

```bash
python script/analyze_errors.py logs/elastic_logs.json analysis
```

### Security Analysis

Identifies security threats such as unauthorized access attempts, SQL injection patterns, and suspicious activities:

```bash
python script/analyze_security.py logs/elastic_logs.json analysis
```

### Performance Analysis

Detects performance issues including high latency, memory pressure, and resource exhaustion:

```bash
python script/analyze_performance.py logs/elastic_logs.json analysis
```

### Running All Analyses

To run all three analyses in sequence:

```bash
python script/run_all_analyses.py logs/elastic_logs.json analysis
```

## Using the Playbook

The playbook encapsulates all three analysis tasks into a single execution. To trigger the playbook:

```bash
python script/trigger_playbook.py playbook/elastic_logs_analysis.yaml logs/elastic_logs.json analysis
```

The playbook creates a single Devin session that performs all analyses and provides a comprehensive summary.

## GitHub Actions Workflows

### Individual Analysis Workflow

The `analyze_logs.yml` workflow triggers three separate analysis jobs when logs are added to the `logs/` folder. Each job runs independently and uploads its results as artifacts.

To manually trigger this workflow:
1. Go to the repository's Actions tab
2. Select "Analyze Elastic Logs"
3. Click "Run workflow"
4. Optionally specify a custom log file path

### Playbook-Based Workflow

The `analyze_logs_playbook.yml` workflow triggers the playbook for a unified analysis experience. This is the recommended approach for production use.

To manually trigger this workflow:
1. Go to the repository's Actions tab
2. Select "Analyze Elastic Logs (Playbook)"
3. Click "Run workflow"
4. Optionally specify a custom log file path

## Understanding Analysis Results

Analysis results are saved to the `analysis/` directory with timestamped filenames:

- `error_analysis_YYYYMMDD_HHMMSS.json` - Error analysis results
- `security_analysis_YYYYMMDD_HHMMSS.json` - Security analysis results
- `performance_analysis_YYYYMMDD_HHMMSS.json` - Performance analysis results
- `playbook_execution_YYYYMMDD_HHMMSS.json` - Playbook execution results

Each result file contains:
- Analysis type and timestamp
- Count of relevant log entries
- Devin session information (including session URL)
- The analyzed log entries

## Types of Issues Detected

### Application Errors

The error analysis identifies:
- Database connection timeouts
- OutOfMemoryError exceptions
- SSL handshake failures
- Transaction rollbacks
- JSON parsing errors

### Security Issues

The security analysis detects:
- Failed login attempts and brute force patterns
- SQL injection attempts
- Cross-site scripting (XSS) attacks
- Unauthorized access to protected endpoints
- Suspicious user agents (e.g., sqlmap)
- Rate limit violations

### Performance Issues

The performance analysis identifies:
- High request latency (>3000ms)
- Memory utilization above 85%
- CPU spikes above 85%
- Slow database queries
- Thread pool exhaustion
- Garbage collection pauses

## Customizing the Analysis

### Adding New Log Files

Place new log files in the `logs/` directory. The files should follow the Elastic Common Schema (ECS) format with fields like:
- `@timestamp` - ISO 8601 timestamp
- `log.level` - Log level (INFO, WARN, ERROR)
- `message` - Log message
- `service.name` - Service identifier
- `host.name` - Host identifier

### Modifying Analysis Prompts

Edit the analysis scripts in the `script/` directory to customize the prompts sent to Devin. The prompts are defined in the `create_analysis_prompt()` functions.

### Extending the Playbook

Edit `playbook/elastic_logs_analysis.yaml` to add new tasks or modify existing ones. The playbook supports template variables for dynamic configuration.

## Troubleshooting

### API Key Issues

If you see "DEVIN_API_KEY environment variable not set":
1. Verify the environment variable is exported
2. For GitHub Actions, check that the secret is properly configured

### No Logs Found

If analyses report no relevant logs:
1. Verify the log file exists and is valid JSON
2. Check that the log file contains entries with the expected fields
3. Regenerate logs using `generate_logs.py`

### GitHub Actions Failures

If workflows fail:
1. Check the workflow logs in the Actions tab
2. Verify the DEVIN_API_KEY secret is configured
3. Ensure the log file path is correct

## Best Practices

1. Always review analysis results before taking action
2. Use the playbook workflow for comprehensive analysis
3. Archive analysis results for historical tracking
4. Regularly update log files to reflect current system state
5. Monitor Devin session URLs for detailed analysis insights

## Support

For issues with this demonstration, please open an issue in the repository or contact the maintainers.
