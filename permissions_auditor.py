import json
import csv
from collections import defaultdict
from datetime import datetime, timedelta
import argparse

# Constants
STALE_DAYS = 90
AUTHORIZED_DEPTS = {'IT', 'Security'}

def load_json(filepath):
    """Load JSON data from file."""
    with open(filepath, 'r') as f:
        return json.load(f)

def load_csv(filepath):
    """Load CSV data from file."""
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f)
        return list(reader)

def build_user_lookup(users_data):
    """Build dictionary keyed by user_id for O(1) lookup."""
    return {user['user_id']: user for user in users_data}

def group_roles_by_user(roles_data):
    """Group all roles per user using defaultdict."""
    user_roles = defaultdict(list)
    for role_entry in roles_data:
        user_id = role_entry['user_id']
        user_roles[user_id].append(role_entry['role'])
    return dict(user_roles)

def check_disabled_with_roles(users_dict, roles_data):
    """Detect disabled users with active roles."""
    users_with_roles = {r['user_id'] for r in roles_data}
    violations = []
    
    for user_id, user in users_dict.items():
        if user['status'] == 'disabled' and user_id in users_with_roles:
            roles = [r['role'] for r in roles_data if r['user_id'] == user_id]
            violations.append({
                'user_id': user_id,
                'username': user['username'],
                'violation_type': 'disabled_with_roles',
                'severity': 'CRITICAL',
                'details': f"Disabled account has {len(roles)} active role(s): {', '.join(roles)}"
            })
    
    return violations

def check_unauthorized_admins(users_dict, roles_data):
    """Detect unauthorized admin access."""
    violations = []
    
    for role_entry in roles_data:
        if 'admin' in role_entry['role'].lower():
            user_id = role_entry['user_id']
            user = users_dict.get(user_id)
            if user and user['department'] not in AUTHORIZED_DEPTS:
                violations.append({
                    'user_id': user_id,
                    'username': user['username'],
                    'violation_type': 'unauthorized_admin',
                    'severity': 'HIGH',
                    'details': f"Admin role assigned to non-authorize department: {user['department']}"
                })
    
    return violations

def check_stale_accounts(users_dict, stale_days=STALE_DAYS):
    """Detect stale accounts (90+ days inactive)."""
    violations = []
    cutoff_date = datetime.now() - timedelta(days=stale_days)
    
    for user_id, user in users_dict.items():
        if user['status'] == 'active':
            try:
                last_login = datetime.strptime(user['last_login'], '%Y-%m-%d')
                days_since_login = (datetime.now() - last_login).days
                if days_since_login > stale_days:
                    violations.append({
                        'user_id': user_id,
                        'username': user['username'],
                        'violation_type': 'stale_account',
                        'severity': 'MEDIUM',
                        'details': f"Account hasn't logged in for {days_since_login} days"
                    })
            except ValueError:
                # Handle invalid date format
                violations.append({
                    'user_id': user_id,
                    'username': user['username'],
                    'violation_type': 'stale_account',
                    'severity': 'MEDIUM',
                    'details': "Invalid last_login date format"
                })
    
    return violations

def check_conflicting_roles(users_dict, roles_data):
    """Detect conflicting roles (e.g., auditor + admin)."""
    violations = []
    user_roles = group_roles_by_user(roles_data)
    
    for user_id, roles in user_roles.items():
        if 'auditor' in roles and 'admin' in roles:
            user = users_dict.get(user_id)
            violations.append({
                'user_id': user_id,
                'username': user['username'] if user else 'Unknown',
                'violation_type': 'conflicting_roles',
                'severity': 'CRITICAL',
                'details': "Has both auditor and admin roles (conflicting responsibilities)"
            })
    
    return violations

def check_excessive_permissions(users_dict, roles_data, max_roles=5):
    """Detect excessive permissions (more than max_roles)."""
    violations = []
    user_roles = group_roles_by_user(roles_data)
    
    for user_id, roles in user_roles.items():
        if len(roles) > max_roles:
            user = users_dict.get(user_id)
            violations.append({
                'user_id': user_id,
                'username': user['username'] if user else 'Unknown',
                'violation_type': 'excessive_permissions',
                'severity': 'MEDIUM',
                'details': f"Has {len(roles)} roles exceeding limit of {max_roles}"
            })
    
    return violations

def generate_json_report(all_violations, users_dict, roles_data):
    """Generate JSON compliance report."""
    report = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_users_audited": len(users_dict),
            "total_role_assignments": len(roles_data),
            "total_violations": len(all_violations),
            "auditor": "IAM Audit System v1.0"
        },
        "violation_summary": {
            "by_severity": {},
            "by_type": {}
        },
        "all_violations": all_violations
    }
    
    # Count violations by severity and type
    for violation in all_violations:
        severity = violation['severity']
        violation_type = violation['violation_type']
        
        report["violation_summary"]["by_severity"].setdefault(severity, 0)
        report["violation_summary"]["by_severity"][severity] += 1
        
        report["violation_summary"]["by_type"].setdefault(violation_type, 0)
        report["violation_summary"]["by_type"][violation_type] += 1
    
    return json.dumps(report, indent=2)

def generate_text_report(all_violations, users_dict, roles_data):
    """Generate human-readable text summary report."""
    # Sort violations by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    all_violations.sort(key=lambda x: severity_order[x['severity']])
    
    # Group by severity
    violations_by_severity = defaultdict(list)
    for violation in all_violations:
        violations_by_severity[violation['severity']].append(violation)
    
    # Count by type
    type_counts = defaultdict(int)
    for violation in all_violations:
        type_counts[violation['violation_type']] += 1
    
    # Build bar chart
    def make_bar(count, max_count=10):
        bar_length = int((count / max_count) * 10)
        return '█' * bar_length
    
    # Format details
    def format_details(violation):
        user_info = f"User: {violation['username']} (ID: {violation['user_id']})"
        type_info = f"Type: {violation['violation_type']}"
        return f"{user_info}\n{type_info}\nDetails: {violation['details']}\n\n"
    
    # Build report sections
    header = "="*70
    title = "USER ACCOUNT & PERMISSIONS AUDIT REPORT"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    auditor = "IAM Audit System v1.0"
    
    executive_summary = f"""
EXECUTIVE SUMMARY
{header}
Total Users Audited: {len(users_dict)}
Total Role Assignments: {len(roles_data)}
Total Violations Found: {len(all_violations)}
"""
    
    severity_breakdown = "\nVIOLATIONS BY SEVERITY\n" + header
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = sum(1 for v in all_violations if v['severity'] == severity)
        severity_breakdown += f"\n{severity:<12} [{count:>3}] {make_bar(count)}"
    
    type_breakdown = "\n\nVIOLATIONS BY TYPE\n" + header
    for violation_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        type_breakdown += f"\n{violation_type:<30} {count}"
    
    detailed_violations = "\n\nDETAILED VIOLATIONS\n" + header
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        severity_violations = violations_by_severity.get(severity, [])
        if not severity_violations:
            continue
            
        detailed_violations += f"\n\n{severity} SEVERITY ({len(severity_violations)} issues)\n" + "-"*50
        for i, violation in enumerate(severity_violations, 1):
            detailed_violations += f"\n\n{i}. {format_details(violation)}"
    
    end_section = "\n\n" + header + "\nEND OF REPORT\n" + header
    
    return f"""{header}
{title}
{header}
Generated: {timestamp}
Auditor: {auditor}

{executive_summary}

{severity_breakdown}

{type_breakdown}

{detailed_violations}

{end_section}"""

def main():
    """Main orchestration function."""
    parser = argparse.ArgumentParser(description='User Account & Permissions Auditor')
    parser.add_argument('--users', default='users.json', help='Path to users data file')
    parser.add_argument('--roles', default='roles.json', help='Path to roles data file')
    args = parser.parse_args()
    
    # Load data
    users_data = load_json(args.users)
    roles_data = load_json(args.roles)
    
    # Build lookups
    users_dict = build_user_lookup(users_data)
    
    # Run all checks
    all_violations = []
    all_violations.extend(check_disabled_with_roles(users_dict, roles_data))
    all_violations.extend(check_unauthorized_admins(users_dict, roles_data))
    all_violations.extend(check_stale_accounts(users_dict))
    all_violations.extend(check_conflicting_roles(users_dict, roles_data))
    all_violations.extend(check_excessive_permissions(users_dict, roles_data))
    
    # Generate reports
    json_report = generate_json_report(all_violations, users_dict, roles_data)
    text_report = generate_text_report(all_violations, users_dict, roles_data)
    
    # Save reports
    with open('audit_report.json', 'w') as f:
        f.write(json_report)
    with open('audit_report.txt', 'w') as f:
        f.write(text_report)
    
    # Console summary
    print(f"Audit complete! Found {len(all_violations)} violations.")
    print(f"Reports saved: audit_report.json, audit_report.txt")

if __name__ == '__main__':
    main