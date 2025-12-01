#!/usr/bin/env python3
"""
Generate 100 Elastic Log entries with various issues for demonstration purposes.

This script creates realistic Elastic Log entries that include:
- Error patterns (500 errors, timeouts, connection failures)
- Security issues (failed auth attempts, suspicious IPs, SQL injection attempts)
- Performance anomalies (slow response times, high memory usage)
"""

import json
import random
from datetime import datetime, timedelta
from typing import Any


def generate_timestamp(base_time: datetime, offset_minutes: int) -> str:
    """Generate an ISO format timestamp with offset from base time."""
    return (base_time + timedelta(minutes=offset_minutes)).isoformat() + "Z"


def generate_normal_log(timestamp: str, index: int) -> dict[str, Any]:
    """Generate a normal log entry without issues."""
    endpoints = ["/api/users", "/api/products", "/api/orders", "/api/health", "/api/search"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    status_codes = [200, 201, 204]
    
    return {
        "@timestamp": timestamp,
        "log_id": f"log-{index:04d}",
        "level": "INFO",
        "service": random.choice(["api-gateway", "user-service", "order-service", "product-service"]),
        "host": f"server-{random.randint(1, 5)}.example.com",
        "message": "Request completed successfully",
        "http": {
            "method": random.choice(methods),
            "endpoint": random.choice(endpoints),
            "status_code": random.choice(status_codes),
            "response_time_ms": random.randint(10, 200)
        },
        "client": {
            "ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        "metadata": {
            "trace_id": f"trace-{random.randint(10000, 99999)}",
            "span_id": f"span-{random.randint(1000, 9999)}"
        }
    }


def generate_error_log(timestamp: str, index: int) -> dict[str, Any]:
    """Generate an error log entry (500 errors, timeouts, connection failures)."""
    error_types = [
        {"status": 500, "message": "Internal server error: database connection pool exhausted"},
        {"status": 502, "message": "Bad gateway: upstream service unavailable"},
        {"status": 503, "message": "Service unavailable: circuit breaker open"},
        {"status": 504, "message": "Gateway timeout: request exceeded 30s limit"},
        {"status": 500, "message": "Internal server error: null pointer exception in OrderProcessor"},
        {"status": 500, "message": "Internal server error: out of memory exception"},
    ]
    
    error = random.choice(error_types)
    
    return {
        "@timestamp": timestamp,
        "log_id": f"log-{index:04d}",
        "level": "ERROR",
        "service": random.choice(["api-gateway", "user-service", "order-service", "product-service"]),
        "host": f"server-{random.randint(1, 5)}.example.com",
        "message": error["message"],
        "http": {
            "method": random.choice(["GET", "POST", "PUT"]),
            "endpoint": random.choice(["/api/users", "/api/orders", "/api/checkout"]),
            "status_code": error["status"],
            "response_time_ms": random.randint(5000, 30000)
        },
        "error": {
            "type": "ApplicationError",
            "stack_trace": f"at com.example.service.Handler.process(Handler.java:{random.randint(50, 500)})",
            "correlation_id": f"err-{random.randint(10000, 99999)}"
        },
        "client": {
            "ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        },
        "metadata": {
            "trace_id": f"trace-{random.randint(10000, 99999)}",
            "span_id": f"span-{random.randint(1000, 9999)}"
        }
    }


def generate_security_log(timestamp: str, index: int) -> dict[str, Any]:
    """Generate a security-related log entry (failed auth, suspicious IPs, SQL injection)."""
    suspicious_ips = ["10.0.0.99", "185.220.101.1", "45.33.32.156", "91.121.87.10"]
    
    security_events = [
        {
            "level": "WARN",
            "message": "Failed authentication attempt - invalid credentials",
            "security": {"event_type": "AUTH_FAILURE", "attempts": random.randint(3, 10)}
        },
        {
            "level": "WARN",
            "message": "Suspicious request pattern detected - possible SQL injection",
            "security": {"event_type": "SQL_INJECTION_ATTEMPT", "payload": "' OR '1'='1"}
        },
        {
            "level": "WARN",
            "message": "Rate limit exceeded from suspicious IP",
            "security": {"event_type": "RATE_LIMIT_EXCEEDED", "requests_per_minute": random.randint(500, 2000)}
        },
        {
            "level": "WARN",
            "message": "Unauthorized access attempt to admin endpoint",
            "security": {"event_type": "UNAUTHORIZED_ACCESS", "target_resource": "/admin/users"}
        },
        {
            "level": "WARN",
            "message": "Potential XSS attack detected in request body",
            "security": {"event_type": "XSS_ATTEMPT", "payload": "<script>alert('xss')</script>"}
        },
        {
            "level": "WARN",
            "message": "Brute force attack detected - multiple failed login attempts",
            "security": {"event_type": "BRUTE_FORCE", "attempts": random.randint(50, 200)}
        },
    ]
    
    event = random.choice(security_events)
    
    return {
        "@timestamp": timestamp,
        "log_id": f"log-{index:04d}",
        "level": event["level"],
        "service": random.choice(["api-gateway", "auth-service", "security-monitor"]),
        "host": f"server-{random.randint(1, 5)}.example.com",
        "message": event["message"],
        "http": {
            "method": random.choice(["POST", "GET"]),
            "endpoint": random.choice(["/api/login", "/api/admin", "/api/users"]),
            "status_code": random.choice([401, 403, 429]),
            "response_time_ms": random.randint(50, 500)
        },
        "security": event["security"],
        "client": {
            "ip": random.choice(suspicious_ips),
            "user_agent": random.choice([
                "curl/7.68.0",
                "python-requests/2.25.1",
                "sqlmap/1.5.2"
            ])
        },
        "metadata": {
            "trace_id": f"trace-{random.randint(10000, 99999)}",
            "span_id": f"span-{random.randint(1000, 9999)}"
        }
    }


def generate_performance_log(timestamp: str, index: int) -> dict[str, Any]:
    """Generate a performance anomaly log entry (slow response, high memory)."""
    performance_issues = [
        {
            "message": "Slow database query detected",
            "performance": {
                "query_time_ms": random.randint(5000, 15000),
                "query": "SELECT * FROM orders WHERE status = 'pending'"
            }
        },
        {
            "message": "High memory usage detected",
            "performance": {
                "memory_used_mb": random.randint(3500, 4000),
                "memory_limit_mb": 4096,
                "gc_pause_ms": random.randint(500, 2000)
            }
        },
        {
            "message": "CPU spike detected",
            "performance": {
                "cpu_percent": random.randint(85, 99),
                "thread_count": random.randint(200, 500)
            }
        },
        {
            "message": "Connection pool exhaustion warning",
            "performance": {
                "active_connections": random.randint(95, 100),
                "max_connections": 100,
                "wait_time_ms": random.randint(1000, 5000)
            }
        },
        {
            "message": "Disk I/O latency spike",
            "performance": {
                "read_latency_ms": random.randint(100, 500),
                "write_latency_ms": random.randint(200, 800),
                "iops": random.randint(50, 100)
            }
        },
    ]
    
    issue = random.choice(performance_issues)
    
    return {
        "@timestamp": timestamp,
        "log_id": f"log-{index:04d}",
        "level": "WARN",
        "service": random.choice(["api-gateway", "database-service", "cache-service"]),
        "host": f"server-{random.randint(1, 5)}.example.com",
        "message": issue["message"],
        "http": {
            "method": "GET",
            "endpoint": random.choice(["/api/reports", "/api/analytics", "/api/export"]),
            "status_code": 200,
            "response_time_ms": random.randint(3000, 10000)
        },
        "performance": issue["performance"],
        "client": {
            "ip": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        },
        "metadata": {
            "trace_id": f"trace-{random.randint(10000, 99999)}",
            "span_id": f"span-{random.randint(1000, 9999)}"
        }
    }


def generate_logs(count: int = 100) -> list[dict[str, Any]]:
    """
    Generate a list of log entries with a mix of normal and problematic logs.
    
    Distribution:
    - 60% normal logs
    - 15% error logs
    - 15% security logs
    - 10% performance logs
    """
    logs = []
    base_time = datetime(2025, 12, 1, 10, 0, 0)
    
    for i in range(count):
        timestamp = generate_timestamp(base_time, i * 5)
        rand = random.random()
        
        if rand < 0.60:
            log = generate_normal_log(timestamp, i + 1)
        elif rand < 0.75:
            log = generate_error_log(timestamp, i + 1)
        elif rand < 0.90:
            log = generate_security_log(timestamp, i + 1)
        else:
            log = generate_performance_log(timestamp, i + 1)
        
        logs.append(log)
    
    return logs


def main() -> None:
    """Generate logs and save to file."""
    random.seed(42)
    
    logs = generate_logs(100)
    
    output_path = "logs/elastic_logs.json"
    with open(output_path, "w") as f:
        json.dump(logs, f, indent=2)
    
    print(f"Generated {len(logs)} log entries")
    print(f"Saved to {output_path}")
    
    error_count = sum(1 for log in logs if log["level"] == "ERROR")
    warn_count = sum(1 for log in logs if log["level"] == "WARN")
    info_count = sum(1 for log in logs if log["level"] == "INFO")
    
    print("\nLog distribution:")
    print(f"  INFO:  {info_count}")
    print(f"  WARN:  {warn_count}")
    print(f"  ERROR: {error_count}")


if __name__ == "__main__":
    main()
