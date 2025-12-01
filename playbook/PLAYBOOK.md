# Elastic Logs Analysis Playbook

A comprehensive playbook for analyzing Elastic Logs to identify errors, security issues, and performance anomalies. This playbook outlines a sequence of analysis tasks that can be executed via Devin's API or manually.

## Overview

This playbook encapsulates three specialized analysis tasks:
1. Error Pattern Analysis
2. Security Issue Detection
3. Performance Anomaly Analysis

Each task generates a detailed report saved to the analysis output directory.

## Configuration

### Inputs

| Parameter | Description | Default Value |
|-----------|-------------|---------------|
| `log_file` | Path to the Elastic Log file to analyze | `logs/elastic_logs.json` |
| `output_dir` | Directory to save analysis results | `analysis` |

### Outputs

The playbook generates the following reports:
- `{output_dir}/error_analysis_report.md`
- `{output_dir}/security_analysis_report.md`
- `{output_dir}/performance_analysis_report.md`
- `{output_dir}/analysis_summary.md`

---

## Task Sequence

### Task 1: Error Pattern Analysis

**Objective:** Analyze logs for error patterns and failures to identify root causes and remediation steps.

**Steps:**

1.1. **Error Frequency Analysis**
   - Count and categorize all ERROR level logs by HTTP status code (500, 502, 503, 504, etc.)
   - Group errors by service name
   - Classify errors by error message type

1.2. **Error Pattern Detection**
   - Identify recurring errors from the same service
   - Detect error cascades (errors that trigger other errors)
   - Find correlation between errors and specific endpoints

1.3. **Root Cause Analysis**
   - For each major error category, identify potential root causes based on error messages and stack traces
   - Suggest remediation steps for each identified root cause

1.4. **Time-based Analysis**
   - Analyze error distribution over time
   - Identify any error spikes or clusters
   - Look for patterns in error timing (e.g., peak hours, maintenance windows)

1.5. **Impact Assessment**
   - Determine which services are most affected by errors
   - Identify endpoints with the highest error rates
   - Estimate user impact based on error frequency and severity

**Output:** Save detailed analysis report to `{output_dir}/error_analysis_report.md`

---

### Task 2: Security Issue Detection

**Objective:** Detect security issues and potential threats in the log data.

**Steps:**

2.1. **Authentication Analysis**
   - Identify failed login attempts and their frequency
   - Detect brute force attack patterns (multiple failed attempts from same IP)
   - Flag unusual authentication patterns (time, location, user agent)

2.2. **Suspicious IP Detection**
   - Identify IPs with high failure rates
   - Look for known malicious IP patterns
   - Detect IPs attempting to access restricted resources

2.3. **Injection Attack Detection**
   - Scan for SQL injection patterns in request parameters
   - Identify XSS (Cross-Site Scripting) attempts
   - Detect command injection attempts
   - Look for path traversal attempts

2.4. **Access Control Violations**
   - Identify attempts to access admin endpoints without authorization
   - Analyze 401/403 response patterns
   - Detect potential privilege escalation attempts

2.5. **Rate Limiting Analysis**
   - Identify IPs exceeding rate limits
   - Detect potential DDoS patterns
   - Flag automated bot activity indicators

2.6. **User Agent Analysis**
   - Identify known attack tools (sqlmap, nikto, etc.)
   - Flag suspicious or malformed user agents
   - Detect bot signatures

2.7. **Severity Classification**
   - Categorize all findings by severity: Critical, High, Medium, Low
   - Prioritize findings for immediate action

**Output:** Save detailed security report to `{output_dir}/security_analysis_report.md`

---

### Task 3: Performance Anomaly Analysis

**Objective:** Identify performance anomalies and bottlenecks in the system.

**Steps:**

3.1. **Response Time Analysis**
   - Calculate average, median, p95, and p99 response times per endpoint
   - Identify endpoints with consistently slow response times
   - Detect response time spikes and their correlation with other events

3.2. **Resource Utilization Analysis**
   - Examine memory usage patterns and identify potential memory leaks
   - Detect CPU utilization spikes
   - Identify connection pool exhaustion events
   - Flag disk I/O latency issues

3.3. **Database Performance**
   - Detect slow queries from log entries
   - Analyze connection pool utilization
   - Identify query timeout patterns

3.4. **Service Health Analysis**
   - Evaluate service availability patterns
   - Identify circuit breaker activations
   - Detect upstream service failures

3.5. **Capacity Planning Insights**
   - Identify peak load times and patterns
   - Perform resource headroom analysis
   - Provide scaling recommendations

3.6. **Performance Trends**
   - Identify degradation patterns over time
   - Find correlation between different performance metrics
   - Detect seasonal or time-based patterns

**Output:** Save detailed performance report to `{output_dir}/performance_analysis_report.md`

---

## Execution

### Via Devin API

Use the `run_playbook.py` script to execute this playbook via Devin's API:

```bash
python script/run_playbook.py --log-file logs/elastic_logs.json --output-dir analysis
```

With a registered playbook ID:

```bash
python script/run_playbook.py --log-file logs/elastic_logs.json --output-dir analysis --playbook-id YOUR_PLAYBOOK_ID
```

### Via GitHub Actions

The playbook can be triggered automatically via the GitHub Actions workflow when new log files are added to the repository. See `github_actions/analyze-logs-playbook.yml` for the workflow configuration.

### Manual Execution

For manual analysis, follow the task sequence above and use the individual analysis scripts:

```bash
# Task 1: Error Analysis
python script/analyze_errors.py --log-file logs/elastic_logs.json

# Task 2: Security Analysis
python script/analyze_security.py --log-file logs/elastic_logs.json

# Task 3: Performance Analysis
python script/analyze_performance.py --log-file logs/elastic_logs.json
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-12-01 | Initial playbook release |
