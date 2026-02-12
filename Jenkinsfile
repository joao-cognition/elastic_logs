pipeline {
    agent {
        docker {
            image 'python:3.11-slim'
            args '-u root'
        }
    }

    triggers {
        pollSCM('H/5 * * * *')
    }

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

    environment {
        DEVIN_API_KEY = credentials('devin-api-key')
        REPORTS_DIR   = 'analysis'
        LOGS_DIR      = 'logs'
        API_URL       = 'https://api.devin.ai/v1/sessions'
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

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

        stage('Install Dependencies') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                sh 'python3 --version'
                sh 'pip install --quiet requests'
            }
        }

        stage('Lint & Syntax Check') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                sh 'pip install --quiet flake8'
                sh 'flake8 script/ --max-line-length=100 --count --show-source --statistics || true'
                sh """
                    for file in ${env.TARGET_LOG_FILES.replaceAll('\n', ' ')}; do
                        python3 -c "
import json, sys
with open('\$file') as f:
    data = json.load(f)
if not isinstance(data, list):
    print('WARN: Expected JSON array in \$file')
    sys.exit(1)
print('Schema OK: \$file (' + str(len(data)) + ' entries)')
"
                    done
                """
            }
        }

        stage('Unit Tests') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                sh 'pip install --quiet pytest pytest-cov'
                sh """
                    python3 -m pytest tests/ \
                        --cov=script \
                        --cov-report=xml:coverage.xml \
                        --cov-report=html:htmlcov \
                        --junitxml=test-results.xml \
                        -v || true
                """
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'test-results.xml'
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: false,
                        keepAll: true,
                        reportDir: 'htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
            }
        }

        stage('Prepare') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            steps {
                sh "mkdir -p ${REPORTS_DIR}"
            }
        }

        stage('Analyze Logs') {
            when {
                expression { env.TARGET_LOG_FILES?.trim() }
            }
            parallel {
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

    post {
        success {
            echo 'Log analysis pipeline completed successfully.'
            slackSend(
                channel: '#log-analysis',
                color: 'good',
                message: "Log analysis passed: ${env.JOB_NAME} #${env.BUILD_NUMBER} (<${env.BUILD_URL}|Open>)"
            )
        }
        failure {
            echo 'Log analysis pipeline failed.'
            slackSend(
                channel: '#log-analysis',
                color: 'danger',
                message: "Log analysis FAILED: ${env.JOB_NAME} #${env.BUILD_NUMBER} (<${env.BUILD_URL}|Open>)"
            )
        }
        always {
            echo "Pipeline finished. Reports are in: ${REPORTS_DIR}/"
            cleanWs()
        }
    }
}

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
