#!/usr/bin/env python3
"""Generate 100 Elastic Log entries with some containing issues for analysis."""

import json
import random
from datetime import datetime, timedelta
from typing import Any


def generate_timestamp(base_time: datetime, offset_minutes: int) -> str:
    """Generate ISO 8601 timestamp."""
    return (base_time + timedelta(minutes=offset_minutes)).isoformat() + "Z"


def generate_normal_log(
    timestamp: str, index: int, service: str, host: str
) -> dict[str, Any]:
    """Generate a normal log entry."""
    messages = [
        "Request processed successfully",
        "User authentication successful",
        "Database query completed",
        "Cache hit for request",
        "Health check passed",
        "Connection established",
        "Session created",
        "Data synchronized",
    ]
    return {
        "@timestamp": timestamp,
        "log": {"level": "INFO"},
        "message": random.choice(messages),
        "service": {"name": service},
        "host": {"name": host},
        "event": {"id": f"evt-{index:04d}", "category": "process"},
        "http": {"response": {"status_code": 200}},
        "user": {"name": f"user_{random.randint(1, 100)}"},
    }


def generate_error_log(
    timestamp: str, index: int, service: str, host: str
) -> dict[str, Any]:
    """Generate an error log entry (issue type 1: application errors)."""
    error_messages = [
        "NullPointerException in UserService.processRequest",
        "Database connection timeout after 30000ms",
        "OutOfMemoryError: Java heap space",
        "Connection refused to downstream service",
        "Failed to parse JSON response",
        "SSL handshake failed",
        "Transaction rollback due to deadlock",
    ]
    return {
        "@timestamp": timestamp,
        "log": {"level": "ERROR"},
        "message": random.choice(error_messages),
        "service": {"name": service},
        "host": {"name": host},
        "event": {"id": f"evt-{index:04d}", "category": "process"},
        "error": {
            "type": "application_error",
            "stack_trace": "at com.example.service.Handler.process(Handler.java:42)",
        },
        "http": {"response": {"status_code": 500}},
    }


def generate_security_log(
    timestamp: str, index: int, service: str, host: str
) -> dict[str, Any]:
    """Generate a security-related log entry (issue type 2: security issues)."""
    security_messages = [
        "Multiple failed login attempts detected from IP 192.168.1.100",
        "Unauthorized access attempt to /admin endpoint",
        "SQL injection pattern detected in request parameter",
        "Suspicious user agent: sqlmap/1.0",
        "Rate limit exceeded for API key",
        "Invalid JWT token signature",
        "Cross-site scripting attempt blocked",
    ]
    return {
        "@timestamp": timestamp,
        "log": {"level": "WARN"},
        "message": random.choice(security_messages),
        "service": {"name": service},
        "host": {"name": host},
        "event": {"id": f"evt-{index:04d}", "category": "authentication"},
        "source": {"ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"},
        "http": {"response": {"status_code": 403}},
        "threat": {"indicator": {"type": "suspicious_activity"}},
    }


def generate_performance_log(
    timestamp: str, index: int, service: str, host: str
) -> dict[str, Any]:
    """Generate a performance-related log entry (issue type 3: performance issues)."""
    perf_messages = [
        "Request latency exceeded threshold: 5000ms",
        "Memory usage at 95% capacity",
        "CPU utilization spike detected: 98%",
        "Slow database query: 3500ms",
        "Thread pool exhausted, requests queued",
        "Garbage collection pause: 2000ms",
        "Disk I/O latency high: 500ms",
    ]
    return {
        "@timestamp": timestamp,
        "log": {"level": "WARN"},
        "message": random.choice(perf_messages),
        "service": {"name": service},
        "host": {"name": host},
        "event": {"id": f"evt-{index:04d}", "category": "process"},
        "performance": {
            "latency_ms": random.randint(3000, 10000),
            "memory_percent": random.randint(85, 99),
            "cpu_percent": random.randint(85, 99),
        },
        "http": {"response": {"status_code": 200}},
    }


def main() -> None:
    """Generate 100 log entries and save to file."""
    random.seed(42)
    base_time = datetime(2025, 12, 1, 10, 0, 0)
    services = ["api-gateway", "user-service", "payment-service", "order-service"]
    hosts = ["prod-server-01", "prod-server-02", "prod-server-03"]

    logs: list[dict[str, Any]] = []

    for i in range(100):
        timestamp = generate_timestamp(base_time, i)
        service = random.choice(services)
        host = random.choice(hosts)

        # Generate different types of logs with some containing issues
        # ~60% normal, ~15% errors, ~15% security, ~10% performance
        rand_val = random.random()
        if rand_val < 0.60:
            log_entry = generate_normal_log(timestamp, i, service, host)
        elif rand_val < 0.75:
            log_entry = generate_error_log(timestamp, i, service, host)
        elif rand_val < 0.90:
            log_entry = generate_security_log(timestamp, i, service, host)
        else:
            log_entry = generate_performance_log(timestamp, i, service, host)

        logs.append(log_entry)

    # Save logs to file
    output_path = "logs/elastic_logs.json"
    with open(output_path, "w") as f:
        json.dump(logs, f, indent=2)

    print(f"Generated {len(logs)} log entries")
    print(f"Saved to {output_path}")

    # Count log types
    error_count = sum(1 for log in logs if log["log"]["level"] == "ERROR")
    warn_count = sum(1 for log in logs if log["log"]["level"] == "WARN")
    info_count = sum(1 for log in logs if log["log"]["level"] == "INFO")

    print("\nLog distribution:")
    print(f"  INFO: {info_count}")
    print(f"  WARN: {warn_count}")
    print(f"  ERROR: {error_count}")


if __name__ == "__main__":
    main()
