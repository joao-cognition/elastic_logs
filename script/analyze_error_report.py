#!/usr/bin/env python3
"""
Error Analysis Script for Elastic Logs.

Analyzes log files to count ERROR entries, group by status_code, service_name,
and error_message, and generates an HTML report with the top 10 most frequent errors.
"""

import json
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def load_logs(log_file: str) -> list[dict[str, Any]]:
    """Load and parse JSON log file.
    
    Args:
        log_file: Path to the JSON log file.
        
    Returns:
        List of log entry dictionaries.
    """
    with open(log_file, 'r') as f:
        return json.load(f)


def filter_errors(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter log entries to only include ERROR level entries.
    
    Args:
        logs: List of all log entries.
        
    Returns:
        List of ERROR level log entries.
    """
    return [log for log in logs if log.get('level') == 'ERROR']


def group_errors(
    errors: list[dict[str, Any]]
) -> dict[str, Counter]:
    """Group errors by status_code, service_name, and error_message.
    
    Args:
        errors: List of ERROR level log entries.
        
    Returns:
        Dictionary with counters for each grouping.
    """
    by_status_code: Counter = Counter()
    by_service_name: Counter = Counter()
    by_error_message: Counter = Counter()
    by_combined: Counter = Counter()
    
    for error in errors:
        status_code = error.get('http', {}).get('status_code', 'Unknown')
        service_name = error.get('service', 'Unknown')
        error_message = error.get('message', 'Unknown')
        
        by_status_code[status_code] += 1
        by_service_name[service_name] += 1
        by_error_message[error_message] += 1
        
        combined_key = (status_code, service_name, error_message)
        by_combined[combined_key] += 1
    
    return {
        'by_status_code': by_status_code,
        'by_service_name': by_service_name,
        'by_error_message': by_error_message,
        'by_combined': by_combined
    }


def generate_html_report(
    total_logs: int,
    total_errors: int,
    grouped: dict[str, Counter],
    output_file: str,
    log_file: str
) -> None:
    """Generate HTML report with error analysis.
    
    Args:
        total_logs: Total number of log entries.
        total_errors: Total number of ERROR entries.
        grouped: Dictionary with grouped error counters.
        output_file: Path to save the HTML report.
        log_file: Path to the source log file.
    """
    top_10_combined = grouped['by_combined'].most_common(10)
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #d32f2f;
            border-bottom: 3px solid #d32f2f;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #1976d2;
            margin-top: 30px;
        }}
        .summary {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }}
        .summary-item {{
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-item .number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .summary-item .label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }}
        th {{
            background-color: #1976d2;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .count {{
            font-weight: bold;
            color: #d32f2f;
        }}
        .rank {{
            background-color: #ffeb3b;
            color: #333;
            padding: 4px 10px;
            border-radius: 15px;
            font-weight: bold;
        }}
        .section {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .metadata {{
            color: #666;
            font-size: 0.9em;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
        }}
    </style>
</head>
<body>
    <h1>Error Analysis Report</h1>
    
    <div class="summary">
        <h2 style="color: white; margin-top: 0;">Summary</h2>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="number">{total_logs}</div>
                <div class="label">Total Log Entries</div>
            </div>
            <div class="summary-item">
                <div class="number">{total_errors}</div>
                <div class="label">ERROR Entries</div>
            </div>
            <div class="summary-item">
                <div class="number">{total_errors / total_logs * 100:.1f}%</div>
                <div class="label">Error Rate</div>
            </div>
            <div class="summary-item">
                <div class="number">{len(grouped['by_combined'])}</div>
                <div class="label">Unique Error Types</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Top 10 Most Frequent Errors</h2>
        <table>
            <thead>
                <tr>
                    <th>Rank</th>
                    <th>Status Code</th>
                    <th>Service Name</th>
                    <th>Error Message</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for i, ((status_code, service_name, error_message), count) in enumerate(top_10_combined, 1):
        html_content += f"""                <tr>
                    <td><span class="rank">{i}</span></td>
                    <td>{status_code}</td>
                    <td>{service_name}</td>
                    <td>{error_message}</td>
                    <td class="count">{count}</td>
                </tr>
"""
    
    html_content += """            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>Errors by Status Code</h2>
        <table>
            <thead>
                <tr>
                    <th>Status Code</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for status_code, count in grouped['by_status_code'].most_common():
        html_content += f"""                <tr>
                    <td>{status_code}</td>
                    <td class="count">{count}</td>
                </tr>
"""
    
    html_content += """            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>Errors by Service Name</h2>
        <table>
            <thead>
                <tr>
                    <th>Service Name</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for service_name, count in grouped['by_service_name'].most_common():
        html_content += f"""                <tr>
                    <td>{service_name}</td>
                    <td class="count">{count}</td>
                </tr>
"""
    
    html_content += """            </tbody>
        </table>
    </div>
    
    <div class="section">
        <h2>Errors by Error Message</h2>
        <table>
            <thead>
                <tr>
                    <th>Error Message</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for error_message, count in grouped['by_error_message'].most_common():
        html_content += f"""                <tr>
                    <td>{error_message}</td>
                    <td class="count">{count}</td>
                </tr>
"""
    
    html_content += f"""            </tbody>
        </table>
    </div>
    
    <div class="metadata">
        <p><strong>Source File:</strong> {log_file}</p>
        <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
</body>
</html>
"""
    
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report saved to: {output_file}")


def main() -> None:
    """Main entry point for the error analysis script."""
    parser = argparse.ArgumentParser(
        description='Analyze ERROR entries in log files and generate HTML report.'
    )
    parser.add_argument(
        '--log-file',
        required=True,
        help='Path to the JSON log file to analyze'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Path to save the HTML report'
    )
    
    args = parser.parse_args()
    
    print(f"Loading logs from: {args.log_file}")
    logs = load_logs(args.log_file)
    total_logs = len(logs)
    print(f"Total log entries: {total_logs}")
    
    errors = filter_errors(logs)
    total_errors = len(errors)
    print(f"Total ERROR entries: {total_errors}")
    
    grouped = group_errors(errors)
    
    print(f"\nGrouped by status_code: {len(grouped['by_status_code'])} unique values")
    print(f"Grouped by service_name: {len(grouped['by_service_name'])} unique values")
    print(f"Grouped by error_message: {len(grouped['by_error_message'])} unique values")
    print(f"Unique error combinations: {len(grouped['by_combined'])}")
    
    print(f"\nTop 10 most frequent errors:")
    for i, ((status_code, service_name, error_message), count) in enumerate(
        grouped['by_combined'].most_common(10), 1
    ):
        print(f"  {i}. [{status_code}] {service_name}: {error_message} ({count} occurrences)")
    
    generate_html_report(total_logs, total_errors, grouped, args.output, args.log_file)


if __name__ == '__main__':
    main()
