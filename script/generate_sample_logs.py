#!/usr/bin/env python3
"""
Generate 20 sample Elastic Log files for demonstration purposes.

This script creates 20 distinct log files, each with different characteristics:
- Different time periods
- Different service focus
- Different issue distributions
"""

import json
import random
from datetime import datetime, timedelta
from typing import Any


def generate_timestamp(base_time: datetime, offset_minutes: int) -> str:
    """Generate an ISO format timestamp with offset from base time."""
    return (base_time + timedelta(minutes=offset_minutes)).isoformat() + "Z"


def generate_normal_log(timestamp: str, index: int, service_focus: str | None = None) -> dict[str, Any]:
    """Generate a normal log entry without issues."""
    endpoints = ["/api/users", "/api/products", "/api/orders", "/api/health", "/api/search"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    status_codes = [200, 201, 204]
    services = ["api-gateway", "user-service", "order-service", "product-service"]
    
    service = service_focus if service_focus else random.choice(services)
    
    return {
        "@timestamp": timestamp,
        "log_id": f"log-{index:04d}",
        "level": "INFO",
        "service": service,
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


def generate_error_log(timestamp: str, index: int, service_focus: str | None = None) -> dict[str, Any]:
    """Generate an error log entry."""
    error_types = [
        {"status": 500, "message": "Internal server error: database connection pool exhausted"},
        {"status": 502, "message": "Bad gateway: upstream service unavailable"},
        {"status": 503, "message": "Service unavailable: circuit breaker open"},
        {"status": 504, "message": "Gateway timeout: request exceeded 30s limit"},
        {"status": 500, "message": "Internal server error: null pointer exception"},
        {"status": 500, "message": "Internal server error: out of memory exception"},
    ]
    services = ["api-gateway", "user-service", "order-service", "product-service"]
    
    error = random.choice(error_types)
    service = service_focus if service_focus else random.choice(services)
    
    return {
        "@timestamp": timestamp,
        "log_id": f"log-{index:04d}",
        "level": "ERROR",
        "service": service,
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
    """Generate a security-related log entry."""
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
    """Generate a performance anomaly log entry."""
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


def generate_logs_for_scenario(
    scenario: dict[str, Any],
    count: int,
    base_time: datetime
) -> list[dict[str, Any]]:
    """Generate logs for a specific scenario with custom distribution."""
    logs = []
    
    normal_pct = scenario.get("normal_pct", 0.60)
    error_pct = scenario.get("error_pct", 0.15)
    security_pct = scenario.get("security_pct", 0.15)
    service_focus = scenario.get("service_focus")
    
    for i in range(count):
        timestamp = generate_timestamp(base_time, i * 5)
        rand = random.random()
        
        if rand < normal_pct:
            log = generate_normal_log(timestamp, i + 1, service_focus)
        elif rand < normal_pct + error_pct:
            log = generate_error_log(timestamp, i + 1, service_focus)
        elif rand < normal_pct + error_pct + security_pct:
            log = generate_security_log(timestamp, i + 1)
        else:
            log = generate_performance_log(timestamp, i + 1)
        
        logs.append(log)
    
    return logs


# Define 20 different scenarios for sample log files
SCENARIOS = [
    {"name": "normal_traffic", "description": "Normal traffic patterns", "normal_pct": 0.85, "error_pct": 0.05, "security_pct": 0.05},
    {"name": "high_error_rate", "description": "High error rate scenario", "normal_pct": 0.40, "error_pct": 0.45, "security_pct": 0.05},
    {"name": "security_incident", "description": "Security incident in progress", "normal_pct": 0.30, "error_pct": 0.10, "security_pct": 0.50},
    {"name": "performance_degradation", "description": "Performance degradation", "normal_pct": 0.40, "error_pct": 0.10, "security_pct": 0.05},
    {"name": "api_gateway_focus", "description": "API Gateway service logs", "normal_pct": 0.70, "error_pct": 0.15, "security_pct": 0.10, "service_focus": "api-gateway"},
    {"name": "user_service_focus", "description": "User Service logs", "normal_pct": 0.65, "error_pct": 0.20, "security_pct": 0.10, "service_focus": "user-service"},
    {"name": "order_service_focus", "description": "Order Service logs", "normal_pct": 0.60, "error_pct": 0.25, "security_pct": 0.05, "service_focus": "order-service"},
    {"name": "product_service_focus", "description": "Product Service logs", "normal_pct": 0.75, "error_pct": 0.15, "security_pct": 0.05, "service_focus": "product-service"},
    {"name": "database_errors", "description": "Database connection issues", "normal_pct": 0.35, "error_pct": 0.50, "security_pct": 0.05},
    {"name": "auth_failures", "description": "Authentication failures", "normal_pct": 0.40, "error_pct": 0.15, "security_pct": 0.40},
    {"name": "ddos_attack", "description": "DDoS attack simulation", "normal_pct": 0.20, "error_pct": 0.20, "security_pct": 0.55},
    {"name": "memory_pressure", "description": "Memory pressure scenario", "normal_pct": 0.45, "error_pct": 0.20, "security_pct": 0.05},
    {"name": "peak_traffic", "description": "Peak traffic period", "normal_pct": 0.55, "error_pct": 0.25, "security_pct": 0.10},
    {"name": "maintenance_window", "description": "During maintenance window", "normal_pct": 0.50, "error_pct": 0.35, "security_pct": 0.05},
    {"name": "deployment_rollout", "description": "During deployment rollout", "normal_pct": 0.45, "error_pct": 0.40, "security_pct": 0.05},
    {"name": "mixed_issues", "description": "Mixed issues scenario", "normal_pct": 0.40, "error_pct": 0.25, "security_pct": 0.20},
    {"name": "recovery_period", "description": "System recovery period", "normal_pct": 0.70, "error_pct": 0.20, "security_pct": 0.05},
    {"name": "sql_injection_attack", "description": "SQL injection attack", "normal_pct": 0.35, "error_pct": 0.10, "security_pct": 0.50},
    {"name": "timeout_issues", "description": "Timeout issues", "normal_pct": 0.40, "error_pct": 0.45, "security_pct": 0.05},
    {"name": "healthy_system", "description": "Healthy system baseline", "normal_pct": 0.90, "error_pct": 0.05, "security_pct": 0.03},
]


def main() -> None:
    """Generate 20 sample log files."""
    import os
    
    logs_dir = "logs"
    os.makedirs(logs_dir, exist_ok=True)
    
    base_date = datetime(2025, 12, 1, 0, 0, 0)
    logs_per_file = 50
    
    print("Generating 20 sample Elastic Log files...")
    print("-" * 50)
    
    for i, scenario in enumerate(SCENARIOS):
        random.seed(42 + i)
        
        file_time = base_date + timedelta(hours=i)
        logs = generate_logs_for_scenario(scenario, logs_per_file, file_time)
        
        filename = f"sample_{i+1:02d}_{scenario['name']}.json"
        filepath = os.path.join(logs_dir, filename)
        
        with open(filepath, "w") as f:
            json.dump(logs, f, indent=2)
        
        error_count = sum(1 for log in logs if log["level"] == "ERROR")
        warn_count = sum(1 for log in logs if log["level"] == "WARN")
        info_count = sum(1 for log in logs if log["level"] == "INFO")
        
        print(f"Created: {filename}")
        print(f"  Description: {scenario['description']}")
        print(f"  Entries: {len(logs)} (INFO: {info_count}, WARN: {warn_count}, ERROR: {error_count})")
    
    print("-" * 50)
    print(f"Successfully generated 20 sample log files in {logs_dir}/")


if __name__ == "__main__":
    main()
