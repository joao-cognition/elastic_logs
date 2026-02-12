// =============================================================================
// Jenkins Pipeline: Elastic Logs Analysis
// =============================================================================
//
// This Jenkinsfile is designed to be fully mappable to a GitHub Actions workflow.
// Each section includes a comment showing its GH Action equivalent.
//
// Mapping overview:
//   Jenkins pipeline { }          →  GH Action: workflow file (.yml)
//   Jenkins agent                 →  GH Action: runs-on
//   Jenkins environment { }       →  GH Action: env / secrets
//   Jenkins triggers { }          →  GH Action: on: (push, paths, etc.)
//   Jenkins stages / stage        →  GH Action: jobs / steps
//   Jenkins parallel { }          →  GH Action: matrix strategy or separate jobs
//   Jenkins post { }              →  GH Action: if: always() / if: failure()
//   Jenkins archiveArtifacts      →  GH Action: actions/upload-artifact
//   Jenkins credentials()         →  GH Action: ${{ secrets.SECRET_NAME }}
//   Jenkins parameters { }        →  GH Action: workflow_dispatch inputs
//   Jenkins when { }              →  GH Action: if: conditions on steps/jobs
// =============================================================================

pipeline {
    // -------------------------------------------------------------------------
    // Agent: Where the pipeline runs
    // GH Action equivalent:
    //   jobs:
    //     analyze:
    //       runs-on: ubuntu-latest
    // -------------------------------------------------------------------------
    agent {
        docker {
            image 'python:3.11-slim'
            args '-u root'
        }
    }

    // -------------------------------------------------------------------------
    // Triggers: When the pipeline runs
    // GH Action equivalent:
    //   on:
    //     push:
    //       paths:
    //         - 'logs/**'
    //     workflow_dispatch:
    //       inputs:
    //         log_file:
    //           description: 'Path to log file'
    //           required: false
    // -------------------------------------------------------------------------
    triggers {
        pollSCM('H/5 * * * *')
    }

    // -------------------------------------------------------------------------
    // Parameters: Manual trigger inputs
    // GH Action equivalent:
    //   on:
    //     workflow_dispatch:
    //       inputs:
    //         log_file:
    //           description: 'Path to a specific log file to analyze'
    //           required: false
    //           type: string
    //         analysis_type:
    //           description: 'Type of analysis to run'
    //           required: false
    //           default: 'all'
    //           type: choice
    //           options: [all, error, performance, security]
    // -------------------------------------------------------------------------
    parameters {
        string(
            name: 'LOG_FILE',
            defaultValue: '',
            description: 'Path to a specific log file to analyze (leave empty for auto-detect)'
        )
        choice(
            name: 'ANALYSIS_TYPE',
            choices: ['all', 'error', 'performance', 'security'],
            description: 'Type of analysis to run'
        )
    }

    // -------------------------------------------------------------------------
    // Environment: Global variables and secrets
    // GH Action equivalent:
    //   env:
    //     REPORTS_DIR: analysis
    //     LOGS_DIR: logs
    //   jobs:
    //     analyze:
    //       env:
    //         DEVIN_API_KEY: ${{ secrets.DEVIN_API_KEY }}
    // -------------------------------------------------------------------------
    environment {
        DEVIN_API_KEY = credentials('devin-api-key')
        REPORTS_DIR   = 'analysis'
        LOGS_DIR      = 'logs'
        API_URL       = 'https://api.devin.ai/v1/sessions'
    }

    // -------------------------------------------------------------------------
    // Options: Pipeline-level settings
    // GH Action equivalent:
    //   jobs:
    //     analyze:
    //       timeout-minutes: 30
    //       concurrency:
    //         group: log-analysis-${{ github.ref }}
    //         cancel-in-progress: true
    // -------------------------------------------------------------------------
    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
    }

    stages {
        // =====================================================================
        // Stage 1: Checkout
        // GH Action equivalent:
        //   steps:
        //     - name: Checkout code
        //       uses: actions/checkout@v4
        //       with:
        //         fetch-depth: 0
        // =====================================================================
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        // =====================================================================
        // Stage 2: Detect Changed Log Files
        // GH Action equivalent:
        //   steps:
        //     - name: Get changed files
        //       id: changed-files
        //       uses: tj-actions/changed-files@v41
        //       with:
        //         files: |
        //           logs/*.json
        //         diff_relative: true
        //
        //     - name: Set log file
        //       id: set-log-file
        //       run: |
        //         if [ -n "${{ inputs.log_file }}" ]; then
        //           echo "log_file=${{ inputs.log_file }}" >> $GITHUB_OUTPUT
        //         else
        //           echo "log_file=${{ steps.changed-files.outputs.all_changed_files }}" >> $GITHUB_OUTPUT
        //         fi
        // =====================================================================
        stage('Detect Changed Logs') {
            steps {
                script {
                    if (params.LOG_FILE?.trim()) {
                        env.TARGET_LOG_FILES = params.LOG_FILE
                        echo "Using manually specified log file: ${env.TARGET_LOG_FILES}"
                    } else {
                        def changes = sh(
                            script: "git diff --name-only HEAD~1 HEAD -- '${LOGS_DIR}/*.json' || true",
                            returnStdout: true
                        ).trim()

                        if (changes) {
                            env.TARGET_LOG_FILES = changes
                            echo "Detected changed log files:\n${changes}"
                        } else {
                            env.TARGET_LOG_FILES = ''
                            echo "No changed log files detected"
                        }
                    }
                }
            }
        }

        // =====================================================================
        // Stage 3: Validate Input
        // GH Action equivalent:
        //   steps:
        //     - name: Validate log files exist
        //       if: steps.set-log-file.outputs.log_file != ''
        //       run: |
        //         for file in ${{ steps.set-log-file.outputs.log_file }}; do
        //           if [ ! -f "$file" ]; then
        //             echo "::error::Log file not found: $file"
        //             exit 1
        //           fi
        //           python3 -c "import json; json.load(open('$file'))"
        //         done
        // =====================================================================
        stage('Validate') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                script {
                    env.TARGET_LOG_FILES.split('\n').each { logFile ->
                        logFile = logFile.trim()
                        if (logFile && !fileExists(logFile)) {
                            error("Log file not found: ${logFile}")
                        }
                    }
                    sh """
                        for file in ${env.TARGET_LOG_FILES.replaceAll('\n', ' ')}; do
                            python3 -c "import json; json.load(open('\$file'))" || exit 1
                            echo "Validated: \$file"
                        done
                    """
                }
            }
        }

        // =====================================================================
        // Stage 4: Prepare Environment
        // GH Action equivalent:
        //   steps:
        //     - name: Set up Python
        //       uses: actions/setup-python@v5
        //       with:
        //         python-version: '3.11'
        //
        //     - name: Create output directory
        //       run: mkdir -p analysis
        // =====================================================================
        stage('Prepare') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                sh "mkdir -p ${REPORTS_DIR}"
                sh 'python3 --version'
            }
        }

        // =====================================================================
        // Stage 5: Run Analysis (Parallel)
        // GH Action equivalent (using matrix strategy):
        //   jobs:
        //     analyze:
        //       strategy:
        //         matrix:
        //           analysis_type: [error, performance, security]
        //       steps:
        //         - name: Run ${{ matrix.analysis_type }} analysis
        //           env:
        //             DEVIN_API_KEY: ${{ secrets.DEVIN_API_KEY }}
        //           run: |
        //             python3 << 'EOF'
        //             ...create Devin session for matrix.analysis_type...
        //             EOF
        //
        // Or using separate jobs with needs:
        //   jobs:
        //     error-analysis:
        //       ...
        //     performance-analysis:
        //       ...
        //     security-analysis:
        //       ...
        // =====================================================================
        stage('Analyze Logs') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            parallel {
                // ---------------------------------------------------------
                // Error Analysis
                // GH Action equivalent (matrix value: error):
                //   - name: Run error analysis
                //     run: |
                //       python3 << 'EOF'
                //       # Count ERROR entries, group by status/service/message
                //       EOF
                // ---------------------------------------------------------
                stage('Error Analysis') {
                    when {
                        expression {
                            params.ANALYSIS_TYPE == 'all' || params.ANALYSIS_TYPE == 'error'
                        }
                    }
                    steps {
                        script {
                            runAnalysis('error', env.TARGET_LOG_FILES)
                        }
                    }
                }

                // ---------------------------------------------------------
                // Performance Analysis
                // GH Action equivalent (matrix value: performance):
                //   - name: Run performance analysis
                //     run: |
                //       python3 << 'EOF'
                //       # Calculate response_time stats: min, max, avg, p95, p99
                //       EOF
                // ---------------------------------------------------------
                stage('Performance Analysis') {
                    when {
                        expression {
                            params.ANALYSIS_TYPE == 'all' || params.ANALYSIS_TYPE == 'performance'
                        }
                    }
                    steps {
                        script {
                            runAnalysis('performance', env.TARGET_LOG_FILES)
                        }
                    }
                }

                // ---------------------------------------------------------
                // Security Analysis
                // GH Action equivalent (matrix value: security):
                //   - name: Run security analysis
                //     run: |
                //       python3 << 'EOF'
                //       # Find 401/403 entries, suspicious IPs, SQL/XSS patterns
                //       EOF
                // ---------------------------------------------------------
                stage('Security Analysis') {
                    when {
                        expression {
                            params.ANALYSIS_TYPE == 'all' || params.ANALYSIS_TYPE == 'security'
                        }
                    }
                    steps {
                        script {
                            runAnalysis('security', env.TARGET_LOG_FILES)
                        }
                    }
                }
            }
        }

        // =====================================================================
        // Stage 6: Archive Reports
        // GH Action equivalent:
        //   steps:
        //     - name: Upload analysis reports
        //       if: always()
        //       uses: actions/upload-artifact@v4
        //       with:
        //         name: analysis-reports
        //         path: analysis/*.html
        //         retention-days: 30
        // =====================================================================
        stage('Archive Reports') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                archiveArtifacts(
                    artifacts: "${REPORTS_DIR}/*.html",
                    allowEmptyArchive: true,
                    fingerprint: true
                )
            }
        }
    }

    // =========================================================================
    // Post: Actions that run after the pipeline completes
    // GH Action equivalent:
    //   jobs:
    //     analyze:
    //       steps:
    //         - name: Notify on success
    //           if: success()
    //           run: echo "Analysis completed successfully"
    //
    //         - name: Notify on failure
    //           if: failure()
    //           run: echo "::error::Analysis pipeline failed"
    //
    //         - name: Cleanup
    //           if: always()
    //           run: echo "Pipeline finished"
    // =========================================================================
    post {
        success {
            echo 'Log analysis pipeline completed successfully.'
        }
        failure {
            echo 'Log analysis pipeline failed. Check the logs for details.'
        }
        always {
            echo "Pipeline finished. Reports are in: ${REPORTS_DIR}/"
            cleanWs()
        }
    }
}

// =============================================================================
// Shared function: Trigger a Devin analysis session
// GH Action equivalent:
//   This logic lives inline in the step's `run:` block or in a reusable
//   composite action / workflow_call.
//
//   For composite action (reusable):
//     # .github/actions/run-analysis/action.yml
//     inputs:
//       analysis_type:
//         required: true
//       log_file:
//         required: true
//     runs:
//       using: composite
//       steps:
//         - run: |
//             python3 << 'EOF'
//             import json, os, time
//             from urllib.request import Request, urlopen
//             from datetime import datetime, timezone
//             ...build prompt and call API...
//             EOF
// =============================================================================
def runAnalysis(String analysisType, String logFiles) {
    def timestamp = new Date().format("yyyyMMdd_HHmmss", TimeZone.getTimeZone('UTC'))

    logFiles.split('\n').each { logFile ->
        logFile = logFile.trim()
        if (!logFile) return

        echo "Running ${analysisType} analysis on ${logFile}..."

        def prompt = buildPrompt(analysisType, logFile, timestamp)

        sh """
            python3 << 'PYEOF'
import json
import time
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import os

api_key = os.environ.get("DEVIN_API_KEY")
prompt = '''${prompt}'''

payload = {"prompt": prompt}
data = json.dumps(payload).encode("utf-8")
request = Request(
    "${API_URL}",
    data=data,
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    },
    method="POST",
)

max_retries = 3
for attempt in range(max_retries):
    try:
        with urlopen(request, timeout=60) as response:
            result = json.loads(response.read().decode("utf-8"))
            print(f"  Session URL: {result['url']}")
            break
    except (HTTPError, URLError) as e:
        if attempt < max_retries - 1:
            wait = 2 ** attempt
            print(f"  Retry {attempt + 1}/{max_retries} after error: {e}")
            time.sleep(wait)
        else:
            print(f"  Failed after {max_retries} attempts: {e}")
            raise
PYEOF
        """
    }
}

// =============================================================================
// Prompt builder: Generates analysis-specific prompts
// GH Action equivalent:
//   Inline in the run: block, or as environment variables per matrix entry:
//     env:
//       ERROR_PROMPT: "Count all entries with level='ERROR'..."
//       PERF_PROMPT: "Calculate response_time stats..."
//       SECURITY_PROMPT: "Find status_code=401/403 entries..."
// =============================================================================
def buildPrompt(String analysisType, String logFile, String timestamp) {
    def prompts = [
        error: "@elastic_logs Read ${logFile}. Count all entries with level='ERROR'. " +
               "Group by: status_code, service_name, error_message. " +
               "List top 10 most frequent errors. " +
               "Save as error_report_${timestamp}.html in analysis/",

        performance: "@elastic_logs Read ${logFile}. Calculate response_time stats: min, max, avg, p95, p99. " +
                     "List slowest 10 endpoints. Identify any response_time > 1000ms. " +
                     "Save as performance_report_${timestamp}.html in analysis/",

        security: "@elastic_logs Read ${logFile}. Find: status_code=401/403 entries, " +
                  "unique IPs with >10 failed requests, any SQL/XSS patterns in request_path. " +
                  "Save as security_report_${timestamp}.html in analysis/"
    ]

    return prompts[analysisType]
}
