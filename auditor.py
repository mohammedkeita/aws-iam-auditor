"""
AWS IAM Least-Privilege Auditor

Scans AWS IAM users and roles for over-permissioned policies and generates
a Markdown compliance report.
"""

import boto3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


# Sensitive actions that warrant extra scrutiny when paired with Resource: "*"
PRIVILEGE_ESCALATION_ACTIONS = {
    'iam:passrole',
    'iam:createrole',
    'iam:attachuserpolicy',
    'iam:attachrolepolicy',
    'iam:putuserpolicy',
    'iam:putrolepolicy',
    'iam:createaccesskey',
    'sts:assumerole',
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

# NIST 800-53 Rev. 5 controls this auditor helps assess
NIST_CONTROLS = [
    ('AC-2',  'Account Management — identifies user/role inventory and policies'),
    ('AC-3',  'Access Enforcement — detects overly permissive Allow statements'),
    ('AC-6',  'Least Privilege — flags wildcard actions and resources'),
    ('AU-2',  'Event Logging — output supports audit recordkeeping'),
    ('AU-6',  'Audit Review — provides reviewable findings with severity'),
    ('CM-7',  'Least Functionality — surfaces unneeded permissions'),
]


# ---------- AWS helpers ----------

def get_iam_client():
    return boto3.client('iam')


def get_account_id():
    return boto3.client('sts').get_caller_identity()['Account']


def list_users(iam):
    users = []
    for page in iam.get_paginator('list_users').paginate():
        users.extend(page['Users'])
    return users


def list_roles(iam):
    roles = []
    for page in iam.get_paginator('list_roles').paginate():
        roles.extend(page['Roles'])
    return [r for r in roles if not r['RoleName'].startswith('AWSServiceRoleFor')]


def get_managed_policy_document(iam, policy_arn):
    policy = iam.get_policy(PolicyArn=policy_arn)['Policy']
    version_id = policy['DefaultVersionId']
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return version['PolicyVersion']['Document']


def get_user_policies(iam, username):
    policies = []
    for p in iam.list_attached_user_policies(UserName=username)['AttachedPolicies']:
        policies.append({
            'name': p['PolicyName'],
            'type': 'managed',
            'document': get_managed_policy_document(iam, p['PolicyArn']),
        })
    for name in iam.list_user_policies(UserName=username)['PolicyNames']:
        doc = iam.get_user_policy(UserName=username, PolicyName=name)
        policies.append({'name': name, 'type': 'inline', 'document': doc['PolicyDocument']})
    return policies


def get_role_policies(iam, role_name):
    policies = []
    for p in iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']:
        policies.append({
            'name': p['PolicyName'],
            'type': 'managed',
            'document': get_managed_policy_document(iam, p['PolicyArn']),
        })
    for name in iam.list_role_policies(RoleName=role_name)['PolicyNames']:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        policies.append({'name': name, 'type': 'inline', 'document': doc['PolicyDocument']})
    return policies


# ---------- Analysis ----------

def normalize_to_list(value):
    if isinstance(value, list):
        return value
    return [value]


def analyze_statement(statement):
    findings = []
    if statement.get('Effect') != 'Allow':
        return findings

    actions = normalize_to_list(statement.get('Action', []))
    resources = normalize_to_list(statement.get('Resource', []))
    actions_lower = [a.lower() for a in actions]
    has_full_wildcard_action = '*' in actions
    has_wildcard_resource = '*' in resources

    if has_full_wildcard_action and has_wildcard_resource:
        findings.append({
            'severity': 'CRITICAL',
            'reason': 'Full administrative access: Action "*" on Resource "*"',
        })
        return findings

    for action in actions_lower:
        if action in PRIVILEGE_ESCALATION_ACTIONS and has_wildcard_resource:
            findings.append({
                'severity': 'HIGH',
                'reason': f'Privilege escalation risk: "{action}" allowed on Resource "*"',
            })

    for action in actions:
        if action.endswith(':*') and has_wildcard_resource:
            findings.append({
                'severity': 'HIGH',
                'reason': f'Service-level wildcard: "{action}" on Resource "*"',
            })

    if has_wildcard_resource and not findings:
        findings.append({
            'severity': 'MEDIUM',
            'reason': f'Wildcard resource "*" used with actions: {actions}',
        })

    return findings


def analyze_policy(policy):
    findings = []
    statements = normalize_to_list(policy['document'].get('Statement', []))
    for statement in statements:
        for f in analyze_statement(statement):
            f['policy_name'] = policy['name']
            f['policy_type'] = policy['type']
            findings.append(f)
    return findings


# ---------- Report building ----------

def escape_md(text):
    """Escape pipe characters so they don't break Markdown tables."""
    return str(text).replace('|', '\\|')


def build_report(account_id, scan_results):
    """
    Build the full Markdown report.
    scan_results: list of dicts with keys 'type', 'name', 'findings'.
    """
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    # Count findings by severity
    severity_counts = Counter()
    for entry in scan_results:
        for f in entry['findings']:
            severity_counts[f['severity']] += 1
    total = sum(severity_counts.values())

    lines = []
    lines.append('# AWS IAM Audit Report')
    lines.append('')
    lines.append(f'**Scan Date:** {timestamp}  ')
    lines.append(f'**Account ID:** {account_id}  ')
    lines.append(f'**Total Findings:** {total}')
    lines.append('')
    lines.append('## Summary')
    lines.append('')
    lines.append('| Severity | Count |')
    lines.append('|----------|-------|')
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        lines.append(f'| {severity} | {severity_counts.get(severity, 0)} |')
    lines.append('')
    lines.append('## Findings')
    lines.append('')

    # Sort entries: those with findings first, then alphabetical
    sorted_entries = sorted(
        scan_results,
        key=lambda e: (len(e['findings']) == 0, e['type'], e['name']),
    )

    for entry in sorted_entries:
        lines.append(f"### {entry['type']}: `{entry['name']}`")
        lines.append('')
        if not entry['findings']:
            lines.append('_No findings._')
            lines.append('')
            continue

        findings = sorted(entry['findings'], key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))
        lines.append('| Severity | Policy | Type | Issue |')
        lines.append('|----------|--------|------|-------|')
        for f in findings:
            lines.append(
                f"| {f['severity']} "
                f"| {escape_md(f['policy_name'])} "
                f"| {f['policy_type']} "
                f"| {escape_md(f['reason'])} |"
            )
        lines.append('')

    # NIST mapping footer
    lines.append('## NIST 800-53 Rev. 5 Control Mapping')
    lines.append('')
    lines.append('This audit supports assessment of the following controls:')
    lines.append('')
    lines.append('| Control | Description |')
    lines.append('|---------|-------------|')
    for control_id, description in NIST_CONTROLS:
        lines.append(f'| {control_id} | {description} |')
    lines.append('')
    lines.append('---')
    lines.append('_Generated by aws-iam-auditor_')

    return '\n'.join(lines)


# ---------- Orchestration ----------

def run_audit():
    iam = get_iam_client()
    account_id = get_account_id()
    scan_results = []

    for user in list_users(iam):
        findings = []
        for policy in get_user_policies(iam, user['UserName']):
            findings.extend(analyze_policy(policy))
        scan_results.append({'type': 'User', 'name': user['UserName'], 'findings': findings})

    for role in list_roles(iam):
        findings = []
        for policy in get_role_policies(iam, role['RoleName']):
            findings.extend(analyze_policy(policy))
        scan_results.append({'type': 'Role', 'name': role['RoleName'], 'findings': findings})

    return account_id, scan_results


def save_report(report_text):
    reports_dir = Path(__file__).parent / 'reports'
    reports_dir.mkdir(exist_ok=True)
    filename = f"iam-audit-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md"
    path = reports_dir / filename
    path.write_text(report_text)
    return path


def main():
    print("Running IAM audit...")
    account_id, scan_results = run_audit()

    print("Building report...")
    report = build_report(account_id, scan_results)

    path = save_report(report)
    print(f"✓ Report saved to: {path}")

    # Quick console summary
    total = sum(len(e['findings']) for e in scan_results)
    print(f"  Scanned {len(scan_results)} principal(s), found {total} issue(s)")


if __name__ == "__main__":
    main()