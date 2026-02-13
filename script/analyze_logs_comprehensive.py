#!/usr/bin/env python3
"""
Comprehensive Elastic Logs Analysis Script

This script analyzes Elastic logs to identify errors, security issues, and performance anomalies.
It generates detailed HTML and Markdown reports for each analysis type.

Author: Devin AI
Date: 2025-12-04
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from statistics import mean, median, stdev
from typing import Any, Optional


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """
    Load and parse the JSON log file.

    Args:
        log_file: Path to the JSON log file.

    Returns:
        List of log entry dictionaries.
    """
    with open(log_file, 'r') as f:
        return json.load(f)


def calculate_percentile(data: list[float], percentile: float) -> float:
    """
    Calculate the percentile value from a list of numbers.

    Args:
        data: List of numeric values.
        percentile: Percentile to calculate (0-100).

    Returns:
        The percentile value.
    """
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = (percentile / 100) * (len(sorted_data) - 1)
    lower = int(index)
    upper = lower + 1
    if upper >= len(sorted_data):
        return sorted_data[-1]
    weight = index - lower
    return sorted_data[lower] * (1 - weight) + sorted_data[upper] * weight


class ErrorAnalyzer:
    """Analyzes error patterns in log data."""

    def __init__(self, logs: list[dict[str, Any]]) -> None:
        """
        Initialize the error analyzer.

        Args:
            logs: List of log entries to analyze.
        """
        self.logs = logs
        self.errors: list[dict[str, Any]] = []
        self.error_by_status: dict[int, list[dict[str, Any]]] = defaultdict(list)
        self.error_by_service: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.error_by_message: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.error_by_hour: dict[int, list[dict[str, Any]]] = defaultdict(list)

    def analyze(self) -> dict[str, Any]:
        """
        Perform comprehensive error analysis.

        Returns:
            Dictionary containing all error analysis results.
        """
        self._categorize_errors()
        return {
            'total_logs': len(self.logs),
            'total_errors': len(self.errors),
            'error_rate': len(self.errors) / len(self.logs) * 100 if self.logs else 0,
            'by_status_code': self._analyze_by_status(),
            'by_service': self._analyze_by_service(),
            'by_message': self._analyze_by_message(),
            'time_distribution': self._analyze_time_distribution(),
            'error_cascades': self._detect_cascades(),
            'root_causes': self._identify_root_causes(),
            'impact_assessment': self._assess_impact(),
        }

    def _categorize_errors(self) -> None:
        """Categorize all error logs by various dimensions."""
        for log in self.logs:
            if log.get('level') == 'ERROR':
                self.errors.append(log)
                status_code = log.get('http', {}).get('status_code', 0)
                service = log.get('service', 'unknown')
                message = log.get('message', 'unknown')
                timestamp = log.get('@timestamp', '')

                self.error_by_status[status_code].append(log)
                self.error_by_service[service].append(log)
                self.error_by_message[message].append(log)

                if timestamp:
                    try:
                        hour = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
                        self.error_by_hour[hour].append(log)
                    except ValueError:
                        pass

    def _analyze_by_status(self) -> dict[str, Any]:
        """Analyze errors grouped by HTTP status code."""
        result = {}
        for status, errors in sorted(self.error_by_status.items()):
            result[str(status)] = {
                'count': len(errors),
                'percentage': len(errors) / len(self.errors) * 100 if self.errors else 0,
                'services_affected': list(set(e.get('service', 'unknown') for e in errors)),
            }
        return result

    def _analyze_by_service(self) -> dict[str, Any]:
        """Analyze errors grouped by service name."""
        result = {}
        for service, errors in sorted(self.error_by_service.items()):
            result[service] = {
                'count': len(errors),
                'percentage': len(errors) / len(self.errors) * 100 if self.errors else 0,
                'status_codes': list(set(e.get('http', {}).get('status_code', 0) for e in errors)),
                'endpoints': list(set(e.get('http', {}).get('endpoint', '') for e in errors)),
            }
        return result

    def _analyze_by_message(self) -> dict[str, Any]:
        """Analyze errors grouped by error message."""
        result = {}
        for message, errors in sorted(self.error_by_message.items()):
            result[message] = {
                'count': len(errors),
                'percentage': len(errors) / len(self.errors) * 100 if self.errors else 0,
                'services': list(set(e.get('service', 'unknown') for e in errors)),
            }
        return result

    def _analyze_time_distribution(self) -> dict[str, Any]:
        """Analyze error distribution over time."""
        hourly_counts = {h: len(errors) for h, errors in self.error_by_hour.items()}
        peak_hour = max(hourly_counts, key=hourly_counts.get) if hourly_counts else None
        return {
            'hourly_distribution': hourly_counts,
            'peak_hour': peak_hour,
            'peak_count': hourly_counts.get(peak_hour, 0) if peak_hour else 0,
        }

    def _detect_cascades(self) -> list[dict[str, Any]]:
        """Detect potential error cascades."""
        cascades = []
        sorted_errors = sorted(self.errors, key=lambda x: x.get('@timestamp', ''))

        for i in range(len(sorted_errors) - 1):
            current = sorted_errors[i]
            next_err = sorted_errors[i + 1]

            current_time = current.get('@timestamp', '')
            next_time = next_err.get('@timestamp', '')

            if current_time and next_time:
                try:
                    t1 = datetime.fromisoformat(current_time.replace('Z', '+00:00'))
                    t2 = datetime.fromisoformat(next_time.replace('Z', '+00:00'))
                    diff = (t2 - t1).total_seconds()

                    if diff <= 300:
                        cascades.append({
                            'trigger_service': current.get('service'),
                            'trigger_message': current.get('message'),
                            'affected_service': next_err.get('service'),
                            'affected_message': next_err.get('message'),
                            'time_diff_seconds': diff,
                        })
                except ValueError:
                    pass

        return cascades

    def _identify_root_causes(self) -> list[dict[str, Any]]:
        """Identify potential root causes for major error categories."""
        root_causes = []

        for message, errors in self.error_by_message.items():
            cause = {
                'error_type': message,
                'count': len(errors),
                'potential_causes': [],
                'remediation': [],
            }

            if 'out of memory' in message.lower():
                cause['potential_causes'] = [
                    'Memory leak in application',
                    'Insufficient heap size configuration',
                    'Large data processing without streaming',
                ]
                cause['remediation'] = [
                    'Increase JVM heap size',
                    'Implement memory profiling',
                    'Review and optimize memory-intensive operations',
                ]
            elif 'connection pool exhausted' in message.lower():
                cause['potential_causes'] = [
                    'Connection leak in application code',
                    'Pool size too small for load',
                    'Long-running queries blocking connections',
                ]
                cause['remediation'] = [
                    'Increase connection pool size',
                    'Implement connection timeout',
                    'Review query performance and optimize slow queries',
                ]
            elif 'connection refused' in message.lower():
                cause['potential_causes'] = [
                    'Downstream service is down',
                    'Network connectivity issues',
                    'Service overloaded and rejecting connections',
                ]
                cause['remediation'] = [
                    'Implement circuit breaker pattern',
                    'Add retry logic with exponential backoff',
                    'Scale downstream services',
                ]
            elif 'timeout' in message.lower():
                cause['potential_causes'] = [
                    'Upstream service responding slowly',
                    'Network latency issues',
                    'Resource contention',
                ]
                cause['remediation'] = [
                    'Increase timeout thresholds',
                    'Implement async processing',
                    'Add caching layer',
                ]

            root_causes.append(cause)

        return root_causes

    def _assess_impact(self) -> dict[str, Any]:
        """Assess the impact of errors on the system."""
        total_requests = len(self.logs)
        error_count = len(self.errors)

        service_impact = {}
        for service, errors in self.error_by_service.items():
            service_logs = [l for l in self.logs if l.get('service') == service]
            service_impact[service] = {
                'total_requests': len(service_logs),
                'error_count': len(errors),
                'error_rate': len(errors) / len(service_logs) * 100 if service_logs else 0,
            }

        endpoint_errors = defaultdict(int)
        for error in self.errors:
            endpoint = error.get('http', {}).get('endpoint', 'unknown')
            endpoint_errors[endpoint] += 1

        return {
            'overall_error_rate': error_count / total_requests * 100 if total_requests else 0,
            'service_impact': service_impact,
            'most_affected_endpoints': dict(
                sorted(endpoint_errors.items(), key=lambda x: x[1], reverse=True)[:5]
            ),
            'estimated_user_impact': 'HIGH' if error_count / total_requests > 0.1 else 'MEDIUM'
            if error_count / total_requests > 0.05 else 'LOW',
        }


class SecurityAnalyzer:
    """Analyzes security issues in log data."""

    KNOWN_ATTACK_TOOLS = ['sqlmap', 'nikto', 'nmap', 'burp', 'hydra', 'metasploit']
    SUSPICIOUS_IP_PREFIXES = ['185.220.', '45.33.']

    def __init__(self, logs: list[dict[str, Any]]) -> None:
        """
        Initialize the security analyzer.

        Args:
            logs: List of log entries to analyze.
        """
        self.logs = logs
        self.security_events: list[dict[str, Any]] = []
        self.failed_auth: list[dict[str, Any]] = []
        self.injection_attempts: list[dict[str, Any]] = []
        self.rate_limit_violations: list[dict[str, Any]] = []
        self.unauthorized_access: list[dict[str, Any]] = []

    def analyze(self) -> dict[str, Any]:
        """
        Perform comprehensive security analysis.

        Returns:
            Dictionary containing all security analysis results.
        """
        self._categorize_security_events()
        return {
            'total_logs': len(self.logs),
            'security_events_count': len(self.security_events),
            'authentication_analysis': self._analyze_authentication(),
            'suspicious_ips': self._analyze_suspicious_ips(),
            'injection_attacks': self._analyze_injection_attacks(),
            'access_control_violations': self._analyze_access_control(),
            'rate_limiting': self._analyze_rate_limiting(),
            'user_agent_analysis': self._analyze_user_agents(),
            'severity_classification': self._classify_severity(),
        }

    def _categorize_security_events(self) -> None:
        """Categorize all security-related log entries."""
        for log in self.logs:
            security_info = log.get('security', {})
            status_code = log.get('http', {}).get('status_code', 0)

            if security_info or status_code in [401, 403, 429]:
                self.security_events.append(log)

                event_type = security_info.get('event_type', '')

                if status_code == 401 or 'FAILED_LOGIN' in event_type:
                    self.failed_auth.append(log)

                if 'SQL_INJECTION' in event_type or 'XSS' in event_type:
                    self.injection_attempts.append(log)

                if 'RATE_LIMIT' in event_type or status_code == 429:
                    self.rate_limit_violations.append(log)

                if 'UNAUTHORIZED_ACCESS' in event_type or status_code == 403:
                    self.unauthorized_access.append(log)

    def _analyze_authentication(self) -> dict[str, Any]:
        """Analyze authentication-related security events."""
        ip_failures = defaultdict(int)
        for log in self.failed_auth:
            ip = log.get('client', {}).get('ip', 'unknown')
            ip_failures[ip] += 1

        brute_force_candidates = {
            ip: count for ip, count in ip_failures.items() if count >= 3
        }

        return {
            'failed_login_count': len(self.failed_auth),
            'unique_ips_with_failures': len(ip_failures),
            'ip_failure_counts': dict(ip_failures),
            'brute_force_candidates': brute_force_candidates,
            'brute_force_detected': len(brute_force_candidates) > 0,
        }

    def _analyze_suspicious_ips(self) -> dict[str, Any]:
        """Identify and analyze suspicious IP addresses."""
        ip_activity = defaultdict(lambda: {'total': 0, 'errors': 0, 'security_events': 0})

        for log in self.logs:
            ip = log.get('client', {}).get('ip', 'unknown')
            ip_activity[ip]['total'] += 1

            if log.get('level') == 'ERROR':
                ip_activity[ip]['errors'] += 1

            if log in self.security_events:
                ip_activity[ip]['security_events'] += 1

        suspicious_ips = []
        for ip, activity in ip_activity.items():
            is_suspicious = False
            reasons = []

            if any(ip.startswith(prefix) for prefix in self.SUSPICIOUS_IP_PREFIXES):
                is_suspicious = True
                reasons.append('Known suspicious IP range')

            if activity['security_events'] >= 2:
                is_suspicious = True
                reasons.append(f"Multiple security events ({activity['security_events']})")

            error_rate = activity['errors'] / activity['total'] if activity['total'] else 0
            if error_rate > 0.5 and activity['total'] >= 3:
                is_suspicious = True
                reasons.append(f"High error rate ({error_rate:.1%})")

            if is_suspicious:
                suspicious_ips.append({
                    'ip': ip,
                    'total_requests': activity['total'],
                    'error_count': activity['errors'],
                    'security_events': activity['security_events'],
                    'reasons': reasons,
                })

        return {
            'suspicious_ip_count': len(suspicious_ips),
            'suspicious_ips': suspicious_ips,
        }

    def _analyze_injection_attacks(self) -> dict[str, Any]:
        """Analyze SQL injection and XSS attack attempts."""
        sql_injection = []
        xss_attempts = []

        for log in self.injection_attempts:
            security_info = log.get('security', {})
            event_type = security_info.get('event_type', '')

            attack_info = {
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'endpoint': log.get('http', {}).get('endpoint'),
                'payload': security_info.get('payload', 'N/A'),
                'user_agent': log.get('client', {}).get('user_agent'),
            }

            if 'SQL_INJECTION' in event_type:
                sql_injection.append(attack_info)
            elif 'XSS' in event_type:
                xss_attempts.append(attack_info)

        return {
            'sql_injection_attempts': len(sql_injection),
            'sql_injection_details': sql_injection,
            'xss_attempts': len(xss_attempts),
            'xss_details': xss_attempts,
            'total_injection_attempts': len(self.injection_attempts),
        }

    def _analyze_access_control(self) -> dict[str, Any]:
        """Analyze access control violations."""
        violations_by_resource = defaultdict(list)

        for log in self.unauthorized_access:
            security_info = log.get('security', {})
            target = security_info.get('target_resource', log.get('http', {}).get('endpoint', 'unknown'))
            violations_by_resource[target].append({
                'timestamp': log.get('@timestamp'),
                'ip': log.get('client', {}).get('ip'),
                'user_agent': log.get('client', {}).get('user_agent'),
            })

        return {
            'total_violations': len(self.unauthorized_access),
            'violations_by_resource': {k: len(v) for k, v in violations_by_resource.items()},
            'detailed_violations': dict(violations_by_resource),
            'admin_endpoint_attempts': sum(
                1 for log in self.unauthorized_access
                if '/admin' in log.get('security', {}).get('target_resource', '')
            ),
        }

    def _analyze_rate_limiting(self) -> dict[str, Any]:
        """Analyze rate limit violations."""
        ip_violations = defaultdict(int)

        for log in self.rate_limit_violations:
            ip = log.get('client', {}).get('ip', 'unknown')
            ip_violations[ip] += 1

        return {
            'total_violations': len(self.rate_limit_violations),
            'unique_ips': len(ip_violations),
            'violations_by_ip': dict(ip_violations),
            'potential_ddos': any(count >= 5 for count in ip_violations.values()),
        }

    def _analyze_user_agents(self) -> dict[str, Any]:
        """Analyze user agents for attack tools and suspicious patterns."""
        attack_tool_usage = defaultdict(list)
        user_agent_counts = defaultdict(int)

        for log in self.logs:
            ua = log.get('client', {}).get('user_agent', 'unknown')
            user_agent_counts[ua] += 1

            for tool in self.KNOWN_ATTACK_TOOLS:
                if tool.lower() in ua.lower():
                    attack_tool_usage[tool].append({
                        'timestamp': log.get('@timestamp'),
                        'ip': log.get('client', {}).get('ip'),
                        'endpoint': log.get('http', {}).get('endpoint'),
                    })

        return {
            'attack_tools_detected': list(attack_tool_usage.keys()),
            'attack_tool_usage': {k: len(v) for k, v in attack_tool_usage.items()},
            'attack_tool_details': dict(attack_tool_usage),
            'unique_user_agents': len(user_agent_counts),
            'user_agent_distribution': dict(user_agent_counts),
        }

    def _classify_severity(self) -> dict[str, Any]:
        """Classify all findings by severity level."""
        critical = []
        high = []
        medium = []
        low = []

        if self.injection_attempts:
            critical.append({
                'type': 'Injection Attacks',
                'count': len(self.injection_attempts),
                'description': 'SQL injection or XSS attempts detected',
            })

        auth_analysis = self._analyze_authentication()
        if auth_analysis['brute_force_detected']:
            high.append({
                'type': 'Brute Force Attack',
                'count': len(auth_analysis['brute_force_candidates']),
                'description': 'Multiple failed login attempts from same IP',
            })

        if self.unauthorized_access:
            high.append({
                'type': 'Unauthorized Access Attempts',
                'count': len(self.unauthorized_access),
                'description': 'Attempts to access restricted resources',
            })

        if self.rate_limit_violations:
            medium.append({
                'type': 'Rate Limit Violations',
                'count': len(self.rate_limit_violations),
                'description': 'IPs exceeding rate limits',
            })

        ua_analysis = self._analyze_user_agents()
        if ua_analysis['attack_tools_detected']:
            medium.append({
                'type': 'Attack Tool Usage',
                'count': sum(ua_analysis['attack_tool_usage'].values()),
                'description': f"Detected tools: {', '.join(ua_analysis['attack_tools_detected'])}",
            })

        return {
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'summary': {
                'critical_count': len(critical),
                'high_count': len(high),
                'medium_count': len(medium),
                'low_count': len(low),
            },
        }


class PerformanceAnalyzer:
    """Analyzes performance anomalies in log data."""

    SLOW_THRESHOLD_MS = 1000

    def __init__(self, logs: list[dict[str, Any]]) -> None:
        """
        Initialize the performance analyzer.

        Args:
            logs: List of log entries to analyze.
        """
        self.logs = logs
        self.response_times: list[float] = []
        self.performance_warnings: list[dict[str, Any]] = []

    def analyze(self) -> dict[str, Any]:
        """
        Perform comprehensive performance analysis.

        Returns:
            Dictionary containing all performance analysis results.
        """
        self._extract_metrics()
        return {
            'total_logs': len(self.logs),
            'response_time_analysis': self._analyze_response_times(),
            'resource_utilization': self._analyze_resource_utilization(),
            'database_performance': self._analyze_database_performance(),
            'service_health': self._analyze_service_health(),
            'capacity_insights': self._analyze_capacity(),
            'performance_trends': self._analyze_trends(),
        }

    def _extract_metrics(self) -> None:
        """Extract performance metrics from logs."""
        for log in self.logs:
            response_time = log.get('http', {}).get('response_time_ms')
            if response_time is not None:
                self.response_times.append(response_time)

            if log.get('performance') or log.get('level') == 'WARN':
                if 'memory' in log.get('message', '').lower() or \
                   'latency' in log.get('message', '').lower() or \
                   'slow' in log.get('message', '').lower():
                    self.performance_warnings.append(log)

    def _analyze_response_times(self) -> dict[str, Any]:
        """Analyze response time statistics."""
        if not self.response_times:
            return {'error': 'No response time data available'}

        endpoint_times = defaultdict(list)
        for log in self.logs:
            endpoint = log.get('http', {}).get('endpoint', 'unknown')
            response_time = log.get('http', {}).get('response_time_ms')
            if response_time is not None:
                endpoint_times[endpoint].append(response_time)

        endpoint_stats = {}
        for endpoint, times in endpoint_times.items():
            endpoint_stats[endpoint] = {
                'avg': mean(times),
                'min': min(times),
                'max': max(times),
                'p95': calculate_percentile(times, 95),
                'p99': calculate_percentile(times, 99),
                'count': len(times),
                'slow_requests': sum(1 for t in times if t > self.SLOW_THRESHOLD_MS),
            }

        slow_endpoints = {
            ep: stats for ep, stats in endpoint_stats.items()
            if stats['avg'] > self.SLOW_THRESHOLD_MS
        }

        return {
            'overall': {
                'avg': mean(self.response_times),
                'median': median(self.response_times),
                'min': min(self.response_times),
                'max': max(self.response_times),
                'p95': calculate_percentile(self.response_times, 95),
                'p99': calculate_percentile(self.response_times, 99),
                'std_dev': stdev(self.response_times) if len(self.response_times) > 1 else 0,
            },
            'by_endpoint': endpoint_stats,
            'slow_endpoints': slow_endpoints,
            'slow_request_count': sum(1 for t in self.response_times if t > self.SLOW_THRESHOLD_MS),
            'slow_request_percentage': sum(
                1 for t in self.response_times if t > self.SLOW_THRESHOLD_MS
            ) / len(self.response_times) * 100,
        }

    def _analyze_resource_utilization(self) -> dict[str, Any]:
        """Analyze resource utilization patterns."""
        memory_issues = []
        io_issues = []

        for log in self.performance_warnings:
            message = log.get('message', '').lower()
            perf_data = log.get('performance', {})

            if 'memory' in message:
                memory_issues.append({
                    'timestamp': log.get('@timestamp'),
                    'service': log.get('service'),
                    'message': log.get('message'),
                    'response_time_ms': log.get('http', {}).get('response_time_ms'),
                })

            if 'i/o' in message or 'latency' in message:
                io_issues.append({
                    'timestamp': log.get('@timestamp'),
                    'service': log.get('service'),
                    'message': log.get('message'),
                    'read_latency_ms': perf_data.get('read_latency_ms'),
                    'write_latency_ms': perf_data.get('write_latency_ms'),
                    'iops': perf_data.get('iops'),
                })

        return {
            'memory_issues': {
                'count': len(memory_issues),
                'details': memory_issues,
            },
            'io_issues': {
                'count': len(io_issues),
                'details': io_issues,
            },
            'total_performance_warnings': len(self.performance_warnings),
        }

    def _analyze_database_performance(self) -> dict[str, Any]:
        """Analyze database-related performance issues."""
        slow_queries = []
        connection_pool_issues = []

        for log in self.logs:
            message = log.get('message', '').lower()

            if 'slow' in message and ('query' in message or 'database' in message):
                slow_queries.append({
                    'timestamp': log.get('@timestamp'),
                    'service': log.get('service'),
                    'response_time_ms': log.get('http', {}).get('response_time_ms'),
                    'performance': log.get('performance', {}),
                })

            if 'connection pool' in message:
                connection_pool_issues.append({
                    'timestamp': log.get('@timestamp'),
                    'service': log.get('service'),
                    'message': log.get('message'),
                })

        return {
            'slow_queries': {
                'count': len(slow_queries),
                'details': slow_queries,
            },
            'connection_pool_issues': {
                'count': len(connection_pool_issues),
                'details': connection_pool_issues,
            },
        }

    def _analyze_service_health(self) -> dict[str, Any]:
        """Analyze service health patterns."""
        service_stats = defaultdict(lambda: {
            'total': 0, 'errors': 0, 'slow': 0, 'response_times': []
        })

        for log in self.logs:
            service = log.get('service', 'unknown')
            service_stats[service]['total'] += 1

            if log.get('level') == 'ERROR':
                service_stats[service]['errors'] += 1

            response_time = log.get('http', {}).get('response_time_ms')
            if response_time:
                service_stats[service]['response_times'].append(response_time)
                if response_time > self.SLOW_THRESHOLD_MS:
                    service_stats[service]['slow'] += 1

        service_health = {}
        for service, stats in service_stats.items():
            error_rate = stats['errors'] / stats['total'] * 100 if stats['total'] else 0
            avg_response = mean(stats['response_times']) if stats['response_times'] else 0

            health_score = 100
            health_score -= error_rate * 2
            health_score -= min(avg_response / 100, 30)

            service_health[service] = {
                'total_requests': stats['total'],
                'error_count': stats['errors'],
                'error_rate': error_rate,
                'slow_requests': stats['slow'],
                'avg_response_time': avg_response,
                'health_score': max(0, health_score),
                'status': 'HEALTHY' if health_score >= 80 else 'DEGRADED'
                if health_score >= 50 else 'UNHEALTHY',
            }

        return service_health

    def _analyze_capacity(self) -> dict[str, Any]:
        """Analyze capacity and provide scaling recommendations."""
        hourly_load = defaultdict(int)
        for log in self.logs:
            timestamp = log.get('@timestamp', '')
            if timestamp:
                try:
                    hour = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
                    hourly_load[hour] += 1
                except ValueError:
                    pass

        peak_hour = max(hourly_load, key=hourly_load.get) if hourly_load else None
        avg_load = mean(hourly_load.values()) if hourly_load else 0

        recommendations = []
        if self.performance_warnings:
            recommendations.append('Consider scaling up services with performance warnings')

        slow_pct = sum(
            1 for t in self.response_times if t > self.SLOW_THRESHOLD_MS
        ) / len(self.response_times) * 100 if self.response_times else 0

        if slow_pct > 10:
            recommendations.append('High percentage of slow requests - consider horizontal scaling')

        return {
            'hourly_load': dict(hourly_load),
            'peak_hour': peak_hour,
            'peak_load': hourly_load.get(peak_hour, 0) if peak_hour else 0,
            'average_load': avg_load,
            'recommendations': recommendations,
        }

    def _analyze_trends(self) -> dict[str, Any]:
        """Analyze performance trends over time."""
        time_buckets = defaultdict(list)

        for log in self.logs:
            timestamp = log.get('@timestamp', '')
            response_time = log.get('http', {}).get('response_time_ms')

            if timestamp and response_time:
                try:
                    hour = datetime.fromisoformat(timestamp.replace('Z', '+00:00')).hour
                    time_buckets[hour].append(response_time)
                except ValueError:
                    pass

        hourly_avg = {h: mean(times) for h, times in time_buckets.items()}

        trend = 'STABLE'
        if len(hourly_avg) >= 2:
            values = list(hourly_avg.values())
            if values[-1] > values[0] * 1.2:
                trend = 'DEGRADING'
            elif values[-1] < values[0] * 0.8:
                trend = 'IMPROVING'

        return {
            'hourly_average_response_time': hourly_avg,
            'trend': trend,
        }


def generate_html_report(
    title: str,
    analysis_data: dict[str, Any],
    report_type: str,
    timestamp: str
) -> str:
    """
    Generate an HTML report from analysis data.

    Args:
        title: Report title.
        analysis_data: Dictionary containing analysis results.
        report_type: Type of report (error, security, performance).
        timestamp: Timestamp for the report.

    Returns:
        HTML string for the report.
    """
    css = """
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        h3 { color: #7f8c8d; }
        .summary-box { background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; }
        .metric-value { font-size: 2em; font-weight: bold; color: #2980b9; }
        .metric-label { color: #7f8c8d; font-size: 0.9em; }
        .severity-critical { background: #e74c3c; color: white; padding: 5px 10px; border-radius: 3px; }
        .severity-high { background: #e67e22; color: white; padding: 5px 10px; border-radius: 3px; }
        .severity-medium { background: #f39c12; color: white; padding: 5px 10px; border-radius: 3px; }
        .severity-low { background: #27ae60; color: white; padding: 5px 10px; border-radius: 3px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #3498db; color: white; }
        tr:hover { background: #f5f5f5; }
        .status-healthy { color: #27ae60; font-weight: bold; }
        .status-degraded { color: #f39c12; font-weight: bold; }
        .status-unhealthy { color: #e74c3c; font-weight: bold; }
        .recommendation { background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em; }
    </style>
    """

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    {css}
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>Generated: {timestamp}</p>
        <p>Log File: logs/elastic_logs_30_11_25.json</p>
"""

    if report_type == 'error':
        html += _generate_error_html(analysis_data)
    elif report_type == 'security':
        html += _generate_security_html(analysis_data)
    elif report_type == 'performance':
        html += _generate_performance_html(analysis_data)

    html += """
        <div class="footer">
            <p>Generated by Elastic Logs Analysis Tool</p>
        </div>
    </div>
</body>
</html>
"""
    return html


def _generate_error_html(data: dict[str, Any]) -> str:
    """Generate HTML content for error analysis report."""
    html = f"""
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-value">{data['total_logs']}</div>
                <div class="metric-label">Total Logs</div>
            </div>
            <div class="metric">
                <div class="metric-value">{data['total_errors']}</div>
                <div class="metric-label">Total Errors</div>
            </div>
            <div class="metric">
                <div class="metric-value">{data['error_rate']:.1f}%</div>
                <div class="metric-label">Error Rate</div>
            </div>
        </div>

        <h2>Errors by HTTP Status Code</h2>
        <table>
            <tr><th>Status Code</th><th>Count</th><th>Percentage</th><th>Services Affected</th></tr>
"""
    for status, info in data['by_status_code'].items():
        services = ', '.join(info['services_affected'])
        html += f"<tr><td>{status}</td><td>{info['count']}</td><td>{info['percentage']:.1f}%</td><td>{services}</td></tr>"

    html += """
        </table>

        <h2>Errors by Service</h2>
        <table>
            <tr><th>Service</th><th>Error Count</th><th>Error Rate</th><th>Status Codes</th></tr>
"""
    for service, info in data['by_service'].items():
        codes = ', '.join(str(c) for c in info['status_codes'])
        html += f"<tr><td>{service}</td><td>{info['count']}</td><td>{info['percentage']:.1f}%</td><td>{codes}</td></tr>"

    html += """
        </table>

        <h2>Root Cause Analysis</h2>
"""
    for cause in data['root_causes']:
        if cause['potential_causes']:
            html += f"""
        <h3>{cause['error_type']} ({cause['count']} occurrences)</h3>
        <p><strong>Potential Causes:</strong></p>
        <ul>
"""
            for c in cause['potential_causes']:
                html += f"<li>{c}</li>"
            html += "</ul><p><strong>Remediation Steps:</strong></p><ul>"
            for r in cause['remediation']:
                html += f"<li>{r}</li>"
            html += "</ul>"

    impact = data['impact_assessment']
    html += f"""
        <h2>Impact Assessment</h2>
        <div class="summary-box">
            <p><strong>Overall Error Rate:</strong> {impact['overall_error_rate']:.1f}%</p>
            <p><strong>Estimated User Impact:</strong> <span class="severity-{impact['estimated_user_impact'].lower()}">{impact['estimated_user_impact']}</span></p>
        </div>

        <h3>Most Affected Endpoints</h3>
        <table>
            <tr><th>Endpoint</th><th>Error Count</th></tr>
"""
    for endpoint, count in impact['most_affected_endpoints'].items():
        html += f"<tr><td>{endpoint}</td><td>{count}</td></tr>"

    html += "</table>"
    return html


def _generate_security_html(data: dict[str, Any]) -> str:
    """Generate HTML content for security analysis report."""
    severity = data['severity_classification']

    html = f"""
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-value">{data['total_logs']}</div>
                <div class="metric-label">Total Logs</div>
            </div>
            <div class="metric">
                <div class="metric-value">{data['security_events_count']}</div>
                <div class="metric-label">Security Events</div>
            </div>
            <div class="metric">
                <div class="metric-value">{severity['summary']['critical_count']}</div>
                <div class="metric-label">Critical Issues</div>
            </div>
            <div class="metric">
                <div class="metric-value">{severity['summary']['high_count']}</div>
                <div class="metric-label">High Issues</div>
            </div>
        </div>

        <h2>Severity Classification</h2>
"""
    if severity['critical']:
        html += "<h3><span class='severity-critical'>CRITICAL</span></h3><ul>"
        for item in severity['critical']:
            html += f"<li><strong>{item['type']}</strong>: {item['description']} ({item['count']} occurrences)</li>"
        html += "</ul>"

    if severity['high']:
        html += "<h3><span class='severity-high'>HIGH</span></h3><ul>"
        for item in severity['high']:
            html += f"<li><strong>{item['type']}</strong>: {item['description']} ({item['count']} occurrences)</li>"
        html += "</ul>"

    if severity['medium']:
        html += "<h3><span class='severity-medium'>MEDIUM</span></h3><ul>"
        for item in severity['medium']:
            html += f"<li><strong>{item['type']}</strong>: {item['description']} ({item['count']} occurrences)</li>"
        html += "</ul>"

    injection = data['injection_attacks']
    html += f"""
        <h2>Injection Attack Analysis</h2>
        <div class="summary-box">
            <p><strong>SQL Injection Attempts:</strong> {injection['sql_injection_attempts']}</p>
            <p><strong>XSS Attempts:</strong> {injection['xss_attempts']}</p>
        </div>
"""
    if injection['sql_injection_details']:
        html += """
        <h3>SQL Injection Details</h3>
        <table>
            <tr><th>Timestamp</th><th>IP Address</th><th>Endpoint</th><th>Payload</th></tr>
"""
        for detail in injection['sql_injection_details']:
            html += f"<tr><td>{detail['timestamp']}</td><td>{detail['ip']}</td><td>{detail['endpoint']}</td><td><code>{detail['payload']}</code></td></tr>"
        html += "</table>"

    suspicious = data['suspicious_ips']
    html += f"""
        <h2>Suspicious IP Analysis</h2>
        <p>Detected {suspicious['suspicious_ip_count']} suspicious IP addresses</p>
        <table>
            <tr><th>IP Address</th><th>Total Requests</th><th>Security Events</th><th>Reasons</th></tr>
"""
    for ip_info in suspicious['suspicious_ips']:
        reasons = ', '.join(ip_info['reasons'])
        html += f"<tr><td>{ip_info['ip']}</td><td>{ip_info['total_requests']}</td><td>{ip_info['security_events']}</td><td>{reasons}</td></tr>"

    html += "</table>"

    ua = data['user_agent_analysis']
    if ua['attack_tools_detected']:
        html += f"""
        <h2>Attack Tool Detection</h2>
        <div class="recommendation">
            <strong>Warning:</strong> The following attack tools were detected: {', '.join(ua['attack_tools_detected'])}
        </div>
        <table>
            <tr><th>Tool</th><th>Usage Count</th></tr>
"""
        for tool, count in ua['attack_tool_usage'].items():
            html += f"<tr><td>{tool}</td><td>{count}</td></tr>"
        html += "</table>"

    rate = data['rate_limiting']
    html += f"""
        <h2>Rate Limiting Analysis</h2>
        <p><strong>Total Violations:</strong> {rate['total_violations']}</p>
        <p><strong>Unique IPs:</strong> {rate['unique_ips']}</p>
        <p><strong>Potential DDoS:</strong> {'Yes' if rate['potential_ddos'] else 'No'}</p>
"""
    return html


def _generate_performance_html(data: dict[str, Any]) -> str:
    """Generate HTML content for performance analysis report."""
    rt = data['response_time_analysis']
    overall = rt.get('overall', {})

    html = f"""
        <div class="summary-box">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-value">{data['total_logs']}</div>
                <div class="metric-label">Total Requests</div>
            </div>
            <div class="metric">
                <div class="metric-value">{overall.get('avg', 0):.0f}ms</div>
                <div class="metric-label">Avg Response Time</div>
            </div>
            <div class="metric">
                <div class="metric-value">{overall.get('p95', 0):.0f}ms</div>
                <div class="metric-label">P95 Response Time</div>
            </div>
            <div class="metric">
                <div class="metric-value">{rt.get('slow_request_percentage', 0):.1f}%</div>
                <div class="metric-label">Slow Requests</div>
            </div>
        </div>

        <h2>Response Time Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Average</td><td>{overall.get('avg', 0):.2f} ms</td></tr>
            <tr><td>Median</td><td>{overall.get('median', 0):.2f} ms</td></tr>
            <tr><td>Minimum</td><td>{overall.get('min', 0):.2f} ms</td></tr>
            <tr><td>Maximum</td><td>{overall.get('max', 0):.2f} ms</td></tr>
            <tr><td>P95</td><td>{overall.get('p95', 0):.2f} ms</td></tr>
            <tr><td>P99</td><td>{overall.get('p99', 0):.2f} ms</td></tr>
            <tr><td>Standard Deviation</td><td>{overall.get('std_dev', 0):.2f} ms</td></tr>
        </table>

        <h2>Response Time by Endpoint</h2>
        <table>
            <tr><th>Endpoint</th><th>Avg (ms)</th><th>P95 (ms)</th><th>P99 (ms)</th><th>Slow Requests</th></tr>
"""
    for endpoint, stats in rt.get('by_endpoint', {}).items():
        html += f"<tr><td>{endpoint}</td><td>{stats['avg']:.0f}</td><td>{stats['p95']:.0f}</td><td>{stats['p99']:.0f}</td><td>{stats['slow_requests']}</td></tr>"

    html += "</table>"

    if rt.get('slow_endpoints'):
        html += """
        <h2>Slow Endpoints (Avg > 1000ms)</h2>
        <div class="recommendation">
            <strong>Action Required:</strong> The following endpoints have average response times exceeding 1000ms and require optimization.
        </div>
        <table>
            <tr><th>Endpoint</th><th>Avg Response Time</th><th>Request Count</th></tr>
"""
        for endpoint, stats in rt['slow_endpoints'].items():
            html += f"<tr><td>{endpoint}</td><td>{stats['avg']:.0f} ms</td><td>{stats['count']}</td></tr>"
        html += "</table>"

    health = data['service_health']
    html += """
        <h2>Service Health</h2>
        <table>
            <tr><th>Service</th><th>Requests</th><th>Error Rate</th><th>Avg Response</th><th>Health Score</th><th>Status</th></tr>
"""
    for service, stats in health.items():
        status_class = f"status-{stats['status'].lower()}"
        html += f"<tr><td>{service}</td><td>{stats['total_requests']}</td><td>{stats['error_rate']:.1f}%</td><td>{stats['avg_response_time']:.0f}ms</td><td>{stats['health_score']:.0f}</td><td class='{status_class}'>{stats['status']}</td></tr>"

    html += "</table>"

    resource = data['resource_utilization']
    html += f"""
        <h2>Resource Utilization Issues</h2>
        <p><strong>Memory Issues:</strong> {resource['memory_issues']['count']}</p>
        <p><strong>I/O Issues:</strong> {resource['io_issues']['count']}</p>
        <p><strong>Total Performance Warnings:</strong> {resource['total_performance_warnings']}</p>
"""

    db = data['database_performance']
    html += f"""
        <h2>Database Performance</h2>
        <p><strong>Slow Queries Detected:</strong> {db['slow_queries']['count']}</p>
        <p><strong>Connection Pool Issues:</strong> {db['connection_pool_issues']['count']}</p>
"""

    capacity = data['capacity_insights']
    html += f"""
        <h2>Capacity Planning Insights</h2>
        <p><strong>Peak Hour:</strong> {capacity['peak_hour']}:00 UTC</p>
        <p><strong>Peak Load:</strong> {capacity['peak_load']} requests</p>
        <p><strong>Average Load:</strong> {capacity['average_load']:.1f} requests/hour</p>
"""
    if capacity['recommendations']:
        html += "<h3>Recommendations</h3><ul>"
        for rec in capacity['recommendations']:
            html += f"<li class='recommendation'>{rec}</li>"
        html += "</ul>"

    trends = data['performance_trends']
    html += f"""
        <h2>Performance Trends</h2>
        <p><strong>Overall Trend:</strong> <span class="status-{'healthy' if trends['trend'] == 'STABLE' else 'degraded' if trends['trend'] == 'DEGRADING' else 'healthy'}">{trends['trend']}</span></p>
"""
    return html


def generate_markdown_report(
    title: str,
    analysis_data: dict[str, Any],
    report_type: str,
    timestamp: str
) -> str:
    """
    Generate a Markdown report from analysis data.

    Args:
        title: Report title.
        analysis_data: Dictionary containing analysis results.
        report_type: Type of report (error, security, performance).
        timestamp: Timestamp for the report.

    Returns:
        Markdown string for the report.
    """
    md = f"""# {title}

**Generated:** {timestamp}
**Log File:** logs/elastic_logs_30_11_25.json

---

"""
    if report_type == 'error':
        md += _generate_error_markdown(analysis_data)
    elif report_type == 'security':
        md += _generate_security_markdown(analysis_data)
    elif report_type == 'performance':
        md += _generate_performance_markdown(analysis_data)

    md += """
---

*Generated by Elastic Logs Analysis Tool*
"""
    return md


def _generate_error_markdown(data: dict[str, Any]) -> str:
    """Generate Markdown content for error analysis report."""
    md = f"""## Executive Summary

| Metric | Value |
|--------|-------|
| Total Logs | {data['total_logs']} |
| Total Errors | {data['total_errors']} |
| Error Rate | {data['error_rate']:.1f}% |

## Errors by HTTP Status Code

| Status Code | Count | Percentage | Services Affected |
|-------------|-------|------------|-------------------|
"""
    for status, info in data['by_status_code'].items():
        services = ', '.join(info['services_affected'])
        md += f"| {status} | {info['count']} | {info['percentage']:.1f}% | {services} |\n"

    md += """
## Errors by Service

| Service | Error Count | Percentage | Status Codes |
|---------|-------------|------------|--------------|
"""
    for service, info in data['by_service'].items():
        codes = ', '.join(str(c) for c in info['status_codes'])
        md += f"| {service} | {info['count']} | {info['percentage']:.1f}% | {codes} |\n"

    md += "\n## Root Cause Analysis\n\n"
    for cause in data['root_causes']:
        if cause['potential_causes']:
            md += f"### {cause['error_type']} ({cause['count']} occurrences)\n\n"
            md += "**Potential Causes:**\n"
            for c in cause['potential_causes']:
                md += f"- {c}\n"
            md += "\n**Remediation Steps:**\n"
            for r in cause['remediation']:
                md += f"- {r}\n"
            md += "\n"

    impact = data['impact_assessment']
    md += f"""## Impact Assessment

- **Overall Error Rate:** {impact['overall_error_rate']:.1f}%
- **Estimated User Impact:** {impact['estimated_user_impact']}

### Most Affected Endpoints

| Endpoint | Error Count |
|----------|-------------|
"""
    for endpoint, count in impact['most_affected_endpoints'].items():
        md += f"| {endpoint} | {count} |\n"

    return md


def _generate_security_markdown(data: dict[str, Any]) -> str:
    """Generate Markdown content for security analysis report."""
    severity = data['severity_classification']

    md = f"""## Executive Summary

| Metric | Value |
|--------|-------|
| Total Logs | {data['total_logs']} |
| Security Events | {data['security_events_count']} |
| Critical Issues | {severity['summary']['critical_count']} |
| High Issues | {severity['summary']['high_count']} |
| Medium Issues | {severity['summary']['medium_count']} |

## Severity Classification

"""
    if severity['critical']:
        md += "### CRITICAL\n\n"
        for item in severity['critical']:
            md += f"- **{item['type']}**: {item['description']} ({item['count']} occurrences)\n"
        md += "\n"

    if severity['high']:
        md += "### HIGH\n\n"
        for item in severity['high']:
            md += f"- **{item['type']}**: {item['description']} ({item['count']} occurrences)\n"
        md += "\n"

    if severity['medium']:
        md += "### MEDIUM\n\n"
        for item in severity['medium']:
            md += f"- **{item['type']}**: {item['description']} ({item['count']} occurrences)\n"
        md += "\n"

    injection = data['injection_attacks']
    md += f"""## Injection Attack Analysis

- **SQL Injection Attempts:** {injection['sql_injection_attempts']}
- **XSS Attempts:** {injection['xss_attempts']}

"""
    if injection['sql_injection_details']:
        md += """### SQL Injection Details

| Timestamp | IP Address | Endpoint | Payload |
|-----------|------------|----------|---------|
"""
        for detail in injection['sql_injection_details']:
            md += f"| {detail['timestamp']} | {detail['ip']} | {detail['endpoint']} | `{detail['payload']}` |\n"
        md += "\n"

    suspicious = data['suspicious_ips']
    md += f"""## Suspicious IP Analysis

Detected **{suspicious['suspicious_ip_count']}** suspicious IP addresses.

| IP Address | Total Requests | Security Events | Reasons |
|------------|----------------|-----------------|---------|
"""
    for ip_info in suspicious['suspicious_ips']:
        reasons = ', '.join(ip_info['reasons'])
        md += f"| {ip_info['ip']} | {ip_info['total_requests']} | {ip_info['security_events']} | {reasons} |\n"

    ua = data['user_agent_analysis']
    if ua['attack_tools_detected']:
        md += f"""
## Attack Tool Detection

**Warning:** The following attack tools were detected: {', '.join(ua['attack_tools_detected'])}

| Tool | Usage Count |
|------|-------------|
"""
        for tool, count in ua['attack_tool_usage'].items():
            md += f"| {tool} | {count} |\n"

    rate = data['rate_limiting']
    md += f"""
## Rate Limiting Analysis

- **Total Violations:** {rate['total_violations']}
- **Unique IPs:** {rate['unique_ips']}
- **Potential DDoS:** {'Yes' if rate['potential_ddos'] else 'No'}
"""
    return md


def _generate_performance_markdown(data: dict[str, Any]) -> str:
    """Generate Markdown content for performance analysis report."""
    rt = data['response_time_analysis']
    overall = rt.get('overall', {})

    md = f"""## Executive Summary

| Metric | Value |
|--------|-------|
| Total Requests | {data['total_logs']} |
| Avg Response Time | {overall.get('avg', 0):.0f} ms |
| P95 Response Time | {overall.get('p95', 0):.0f} ms |
| Slow Requests | {rt.get('slow_request_percentage', 0):.1f}% |

## Response Time Statistics

| Metric | Value |
|--------|-------|
| Average | {overall.get('avg', 0):.2f} ms |
| Median | {overall.get('median', 0):.2f} ms |
| Minimum | {overall.get('min', 0):.2f} ms |
| Maximum | {overall.get('max', 0):.2f} ms |
| P95 | {overall.get('p95', 0):.2f} ms |
| P99 | {overall.get('p99', 0):.2f} ms |
| Standard Deviation | {overall.get('std_dev', 0):.2f} ms |

## Response Time by Endpoint

| Endpoint | Avg (ms) | P95 (ms) | P99 (ms) | Slow Requests |
|----------|----------|----------|----------|---------------|
"""
    for endpoint, stats in rt.get('by_endpoint', {}).items():
        md += f"| {endpoint} | {stats['avg']:.0f} | {stats['p95']:.0f} | {stats['p99']:.0f} | {stats['slow_requests']} |\n"

    if rt.get('slow_endpoints'):
        md += """
## Slow Endpoints (Avg > 1000ms)

> **Action Required:** The following endpoints have average response times exceeding 1000ms.

| Endpoint | Avg Response Time | Request Count |
|----------|-------------------|---------------|
"""
        for endpoint, stats in rt['slow_endpoints'].items():
            md += f"| {endpoint} | {stats['avg']:.0f} ms | {stats['count']} |\n"

    health = data['service_health']
    md += """
## Service Health

| Service | Requests | Error Rate | Avg Response | Health Score | Status |
|---------|----------|------------|--------------|--------------|--------|
"""
    for service, stats in health.items():
        md += f"| {service} | {stats['total_requests']} | {stats['error_rate']:.1f}% | {stats['avg_response_time']:.0f}ms | {stats['health_score']:.0f} | {stats['status']} |\n"

    resource = data['resource_utilization']
    md += f"""
## Resource Utilization Issues

- **Memory Issues:** {resource['memory_issues']['count']}
- **I/O Issues:** {resource['io_issues']['count']}
- **Total Performance Warnings:** {resource['total_performance_warnings']}
"""

    db = data['database_performance']
    md += f"""
## Database Performance

- **Slow Queries Detected:** {db['slow_queries']['count']}
- **Connection Pool Issues:** {db['connection_pool_issues']['count']}
"""

    capacity = data['capacity_insights']
    md += f"""
## Capacity Planning Insights

- **Peak Hour:** {capacity['peak_hour']}:00 UTC
- **Peak Load:** {capacity['peak_load']} requests
- **Average Load:** {capacity['average_load']:.1f} requests/hour

"""
    if capacity['recommendations']:
        md += "### Recommendations\n\n"
        for rec in capacity['recommendations']:
            md += f"- {rec}\n"

    trends = data['performance_trends']
    md += f"""
## Performance Trends

- **Overall Trend:** {trends['trend']}
"""
    return md


def generate_summary_report(
    error_data: dict[str, Any],
    security_data: dict[str, Any],
    performance_data: dict[str, Any],
    timestamp: str
) -> str:
    """
    Generate a consolidated summary report.

    Args:
        error_data: Error analysis results.
        security_data: Security analysis results.
        performance_data: Performance analysis results.
        timestamp: Timestamp for the report.

    Returns:
        Markdown string for the summary report.
    """
    severity = security_data['severity_classification']
    rt = performance_data['response_time_analysis']
    overall = rt.get('overall', {})

    md = f"""# Elastic Logs Analysis Summary

**Generated:** {timestamp}
**Log File:** logs/elastic_logs_30_11_25.json
**Analysis Period:** 2025-11-30

---

## Overview

This report consolidates findings from error pattern analysis, security issue detection, and performance anomaly analysis of the Elastic logs.

## Key Metrics

| Category | Metric | Value |
|----------|--------|-------|
| **General** | Total Log Entries | {error_data['total_logs']} |
| **Errors** | Total Errors | {error_data['total_errors']} |
| **Errors** | Error Rate | {error_data['error_rate']:.1f}% |
| **Security** | Security Events | {security_data['security_events_count']} |
| **Security** | Critical Issues | {severity['summary']['critical_count']} |
| **Security** | High Issues | {severity['summary']['high_count']} |
| **Performance** | Avg Response Time | {overall.get('avg', 0):.0f} ms |
| **Performance** | P95 Response Time | {overall.get('p95', 0):.0f} ms |
| **Performance** | Slow Requests | {rt.get('slow_request_percentage', 0):.1f}% |

## Critical Findings

### Error Analysis

"""
    if error_data['total_errors'] > 0:
        md += f"- **{error_data['total_errors']} errors** detected ({error_data['error_rate']:.1f}% error rate)\n"
        for cause in error_data['root_causes']:
            if cause['count'] > 0:
                md += f"- {cause['error_type']}: {cause['count']} occurrences\n"
    else:
        md += "- No errors detected\n"

    md += "\n### Security Analysis\n\n"
    if severity['critical']:
        for item in severity['critical']:
            md += f"- **CRITICAL:** {item['type']} - {item['description']}\n"
    if severity['high']:
        for item in severity['high']:
            md += f"- **HIGH:** {item['type']} - {item['description']}\n"
    if not severity['critical'] and not severity['high']:
        md += "- No critical or high severity security issues detected\n"

    md += "\n### Performance Analysis\n\n"
    if rt.get('slow_endpoints'):
        md += f"- **{len(rt['slow_endpoints'])} slow endpoints** identified (avg > 1000ms)\n"
    resource = performance_data['resource_utilization']
    if resource['memory_issues']['count'] > 0:
        md += f"- **{resource['memory_issues']['count']} memory issues** detected\n"
    if resource['io_issues']['count'] > 0:
        md += f"- **{resource['io_issues']['count']} I/O issues** detected\n"

    md += """
## Recommendations

### Immediate Actions (Priority 1)

"""
    if severity['critical']:
        md += "1. **Address injection attacks** - SQL injection attempts detected. Review and strengthen input validation.\n"
    if error_data['error_rate'] > 10:
        md += "2. **Investigate high error rate** - Error rate exceeds 10%. Review error logs and implement fixes.\n"

    md += """
### Short-term Actions (Priority 2)

"""
    if severity['high']:
        md += "1. **Review unauthorized access attempts** - Multiple attempts to access restricted resources detected.\n"
    for cause in error_data['root_causes']:
        if 'connection pool' in cause['error_type'].lower():
            md += "2. **Optimize database connections** - Connection pool exhaustion detected. Consider increasing pool size.\n"
            break

    md += """
### Long-term Actions (Priority 3)

1. **Implement comprehensive monitoring** - Set up alerting for error rates and response times.
2. **Review security policies** - Strengthen rate limiting and access controls.
3. **Capacity planning** - Review resource allocation based on peak load patterns.

## Detailed Reports

- [Error Analysis Report](error_analysis_report.html)
- [Security Analysis Report](security_analysis_report.html)
- [Performance Analysis Report](performance_analysis_report.html)

---

*Generated by Elastic Logs Analysis Tool*
"""
    return md


def main() -> None:
    """Main entry point for the analysis script."""
    import argparse

    parser = argparse.ArgumentParser(description='Analyze Elastic logs')
    parser.add_argument('--log-file', required=True, help='Path to the log file')
    parser.add_argument('--output-dir', default='analysis', help='Output directory for reports')
    args = parser.parse_args()

    if not os.path.exists(args.log_file):
        print(f"Error: Log file not found: {args.log_file}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Loading logs from {args.log_file}...")
    logs = load_logs(args.log_file)
    print(f"Loaded {len(logs)} log entries")

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')

    print("\nPerforming Error Analysis...")
    error_analyzer = ErrorAnalyzer(logs)
    error_data = error_analyzer.analyze()

    print("Performing Security Analysis...")
    security_analyzer = SecurityAnalyzer(logs)
    security_data = security_analyzer.analyze()

    print("Performing Performance Analysis...")
    performance_analyzer = PerformanceAnalyzer(logs)
    performance_data = performance_analyzer.analyze()

    print("\nGenerating reports...")

    error_html = generate_html_report(
        'Error Pattern Analysis Report', error_data, 'error', timestamp
    )
    with open(os.path.join(args.output_dir, 'error_analysis_report.html'), 'w') as f:
        f.write(error_html)

    error_md = generate_markdown_report(
        'Error Pattern Analysis Report', error_data, 'error', timestamp
    )
    with open(os.path.join(args.output_dir, 'error_analysis_report.md'), 'w') as f:
        f.write(error_md)

    security_html = generate_html_report(
        'Security Issue Detection Report', security_data, 'security', timestamp
    )
    with open(os.path.join(args.output_dir, 'security_analysis_report.html'), 'w') as f:
        f.write(security_html)

    security_md = generate_markdown_report(
        'Security Issue Detection Report', security_data, 'security', timestamp
    )
    with open(os.path.join(args.output_dir, 'security_analysis_report.md'), 'w') as f:
        f.write(security_md)

    performance_html = generate_html_report(
        'Performance Anomaly Analysis Report', performance_data, 'performance', timestamp
    )
    with open(os.path.join(args.output_dir, 'performance_analysis_report.html'), 'w') as f:
        f.write(performance_html)

    performance_md = generate_markdown_report(
        'Performance Anomaly Analysis Report', performance_data, 'performance', timestamp
    )
    with open(os.path.join(args.output_dir, 'performance_analysis_report.md'), 'w') as f:
        f.write(performance_md)

    summary_md = generate_summary_report(error_data, security_data, performance_data, timestamp)
    with open(os.path.join(args.output_dir, 'analysis_summary.md'), 'w') as f:
        f.write(summary_md)

    print(f"\nReports generated in {args.output_dir}/:")
    print("  - error_analysis_report.html")
    print("  - error_analysis_report.md")
    print("  - security_analysis_report.html")
    print("  - security_analysis_report.md")
    print("  - performance_analysis_report.html")
    print("  - performance_analysis_report.md")
    print("  - analysis_summary.md")

    print("\n=== Analysis Summary ===")
    print(f"Total Logs: {error_data['total_logs']}")
    print(f"Total Errors: {error_data['total_errors']} ({error_data['error_rate']:.1f}%)")
    print(f"Security Events: {security_data['security_events_count']}")
    print(f"Critical Security Issues: {security_data['severity_classification']['summary']['critical_count']}")
    print(f"Avg Response Time: {performance_data['response_time_analysis']['overall']['avg']:.0f}ms")
    print(f"P95 Response Time: {performance_data['response_time_analysis']['overall']['p95']:.0f}ms")


if __name__ == '__main__':
    main()
