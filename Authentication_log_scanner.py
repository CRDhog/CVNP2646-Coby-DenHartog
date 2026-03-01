#!/usr/bin/env python3
import re
import sys
import json
import time
from collections import Counter
from datetime import datetime

class AuthLogScanner:
    def __init__(self):
        self.parsing_errors = 0
        
    def parse_log(self, log_file):
        """Parse authentication logs and extract structured data."""
        entries = []
        
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:  # Skip empty lines
                    continue
                    
                try:
                    # Parse timestamp (first two space-separated values)
                    parts = line.split(None, 2)
                    if len(parts) < 3:
                        print(f"Warning: Malformed log entry at line {line_num}")
                        self.parsing_errors += 1
                        continue
                        
                    timestamp_str = parts[0] + " " + parts[1]
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    
                    # Parse key=value pairs
                    kv_pairs = {}
                    remaining = parts[2]
                    
                    for pair in remaining.split():
                        if '=' not in pair:
                            print(f"Warning: Missing = in key=value pair at line {line_num}")
                            self.parsing_errors += 1
                            continue
                            
                        key, value = pair.split('=', 1)
                        kv_pairs[key] = value
                    
                    # Validate required fields
                    if 'status' not in kv_pairs:
                        print(f"Warning: Missing status field at line {line_num}")
                        self.parsing_errors += 1
                        continue
                        
                    entries.append({
                        'timestamp': timestamp,
                        'status': kv_pairs.get('status', 'UNKNOWN'),
                        'username': kv_pairs.get('username', 'UNKNOWN'),
                        'ip': kv_pairs.get('ip', 'UNKNOWN'),
                        'event_id': kv_pairs.get('event_id', 'UNKNOWN')
                    })
                    
                except ValueError as e:
                    print(f"Error parsing line {line_num}: {e}")
                    self.parsing_errors += 1
                    continue
                    
        return entries
    
    def analyze_logs(self, entries):
        """Analyze log entries and generate statistics."""
        total_events = len(entries)
        fail_count = sum(1 for e in entries if e['status'] == 'FAIL')
        success_count = total_events - fail_count
        
        # Count failed attempts
        fail_by_user = Counter(e['username'] for e in entries if e['status'] == 'FAIL')
        fail_by_ip = Counter(e['ip'] for e in entries if e['status'] == 'FAIL')
        
        # Top 5 targets
        top_targets = fail_by_user.most_common(5)
        top_ips = fail_by_ip.most_common(5)
        
        # Failure rate
        failure_rate = (fail_count / total_events * 100) if total_events else 0
        
        return {
            'total_events': total_events,
            'success_count': success_count,
            'failure_count': fail_count,
            'failure_rate': failure_rate,
            'top_targets': top_targets,
            'top_ips': top_ips
        }
    
    def generate_json_report(self, stats, analyst_name):
        """Generate a JSON report for SOC analysts."""
        report = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'analyst': analyst_name
            },
            'statistics': stats,
            'top_targets': [
                {'username': u, 'attempts': c} for u, c in stats['top_targets']
            ],
            'top_ips': [
                {'ip': i, 'attempts': c} for i, c in stats['top_ips']
            ]
        }
        return json.dumps(report, indent=2)
    
    def generate_text_report(self, stats):
        """Generate a human-readable text report."""
        report = "Authentication Log Analysis Report\n"
        report += "=" * 70 + "\n\n"
        
        # Summary statistics
        report += "SUMMARY STATISTICS\n"
        report += "-" * 70 + "\n"
        report += f"Total Events Processed: {stats['total_events']}\n"
        report += f"Successful Logins: {stats['success_count']}\n"
        report += f"Failed Logins: {stats['failure_count']}\n"
        report += f"Failure Rate: {stats['failure_rate']:.2f}%\n"
        report += f"Parsing Errors: {self.parsing_errors}\n\n"
        
        # Top targets
        report += "TOP 5 TARGETED ACCOUNTS\n"
        report += "-" * 70 + "\n"
        for username, count in stats['top_targets']:
            report += f"{username}: {count} failed attempts\n"
        report += "\n"
        
        # Top IPs
        report += "TOP 5 ATTACKING IP ADDRESSES\n"
        report += "-" * 70 + "\n"
        for ip, count in stats['top_ips']:
            report += f"{ip}: {count} failed attempts\n"
            
        return report

def main():
    if len(sys.argv) != 3:
        print("Usage: python auth_scanner.py <log_file> <analyst_name>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    analyst_name = sys.argv[2]
    
    scanner = AuthLogScanner()
    entries = scanner.parse_log(log_file)
    stats = scanner.analyze_logs(entries)
    
    # Generate reports
    json_report = scanner.generate_json_report(stats, analyst_name)
    text_report = scanner.generate_text_report(stats)
    
    # Write reports to files
    with open('incident_report.json', 'w') as f:
        f.write(json_report)
    
    with open('incident_report.txt', 'w') as f:
        f.write(text_report)
    
    print("Reports generated successfully!")
    print(f"JSON report saved to incident_report.json")
    print(f"Text report saved to incident_report.txt")

if __name__ == "__main__":
    main()