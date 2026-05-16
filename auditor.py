"""
AWS IAM Least-Privilege Auditor
A tool to scan AWS IAM users and roles for over-permissioned policies.
"""

import boto3


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


def get_iam_client():
    """Return a boto3 IAM client."""
    return boto3.client('iam')


# ---------- Listing ----------

def list_users(iam):
    users = []
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        users.extend(page['Users'])
    return users


def list_roles(iam):
    roles = []
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        roles.extend(page['Roles'])
    return [r for r in roles if not r['RoleName'].startswith('AWSServiceRoleFor')]


# ---------- Fetching policy documents ----------

def get_managed_policy_document(iam, policy_arn):
    """Fetch the JSON document of a managed policy."""
    policy = iam.get_policy(PolicyArn=policy_arn)['Policy']
    version_id = policy['DefaultVersionId']
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return version['PolicyVersion']['Document']


def get_user_policies(iam, username):
    """Return all policies attached to a user with their full documents."""
    policies = []

    # Managed policies
    attached = iam.list_attached_user_policies(UserName=username)
    for p in attached['AttachedPolicies']:
        document = get_managed_policy_document(iam, p['PolicyArn'])
        policies.append({
            'name': p['PolicyName'],
            'type': 'managed',
            'document': document,
        })

    # Inline policies
    inline_names = iam.list_user_policies(UserName=username)['PolicyNames']
    for name in inline_names:
        doc = iam.get_user_policy(UserName=username, PolicyName=name)
        policies.append({
            'name': name,
            'type': 'inline',
            'document': doc['PolicyDocument'],
        })

    return policies


def get_role_policies(iam, role_name):
    """Return all policies attached to a role with their full documents."""
    policies = []

    attached = iam.list_attached_role_policies(RoleName=role_name)
    for p in attached['AttachedPolicies']:
        document = get_managed_policy_document(iam, p['PolicyArn'])
        policies.append({
            'name': p['PolicyName'],
            'type': 'managed',
            'document': document,
        })

    inline_names = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    for name in inline_names:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        policies.append({
            'name': name,
            'type': 'inline',
            'document': doc['PolicyDocument'],
        })

    return policies


# ---------- Analysis ----------

def normalize_to_list(value):
    """Action and Resource can be either a string or a list. Make it always a list."""
    if isinstance(value, list):
        return value
    return [value]


def analyze_statement(statement):
    """
    Analyze a single policy statement and return a list of findings.
    Each finding is a dict with 'severity' and 'reason'.
    """
    findings = []

    # We only care about Allow statements
    if statement.get('Effect') != 'Allow':
        return findings

    actions = normalize_to_list(statement.get('Action', []))
    resources = normalize_to_list(statement.get('Resource', []))

    actions_lower = [a.lower() for a in actions]
    has_full_wildcard_action = '*' in actions
    has_wildcard_resource = '*' in resources

    # CRITICAL: full admin (* on * )
    if has_full_wildcard_action and has_wildcard_resource:
        findings.append({
            'severity': 'CRITICAL',
            'reason': 'Full administrative access: Action "*" on Resource "*"',
        })
        return findings  # No need to check further on this statement

    # HIGH: privilege escalation actions with wildcard resource
    for action in actions_lower:
        if action in PRIVILEGE_ESCALATION_ACTIONS and has_wildcard_resource:
            findings.append({
                'severity': 'HIGH',
                'reason': f'Privilege escalation risk: "{action}" allowed on Resource "*"',
            })

    # HIGH: service-level wildcard (e.g., "ec2:*", "s3:*") on Resource "*"
    for action in actions:
        if action.endswith(':*') and has_wildcard_resource:
            findings.append({
                'severity': 'HIGH',
                'reason': f'Service-level wildcard: "{action}" on Resource "*"',
            })

    # MEDIUM: any wildcard resource without the above patterns being triggered
    if has_wildcard_resource and not findings:
        findings.append({
            'severity': 'MEDIUM',
            'reason': f'Wildcard resource "*" used with actions: {actions}',
        })

    return findings


def analyze_policy(policy):
    """Analyze a full policy document and return all findings."""
    findings = []
    document = policy['document']
    statements = normalize_to_list(document.get('Statement', []))

    for statement in statements:
        statement_findings = analyze_statement(statement)
        for f in statement_findings:
            f['policy_name'] = policy['name']
            f['policy_type'] = policy['type']
        findings.extend(statement_findings)

    return findings


# ---------- Reporting ----------

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def print_findings(principal_type, principal_name, findings):
    """Print findings for a single user or role."""
    print(f"\n  {principal_type}: {principal_name}")
    if not findings:
        print(f"    ✓ No findings")
        return

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

    for f in findings:
        print(f"    [{f['severity']}] {f['policy_name']} ({f['policy_type']})")
        print(f"            → {f['reason']}")


def main():
    iam = get_iam_client()

    print("=" * 60)
    print("AWS IAM Least-Privilege Auditor")
    print("=" * 60)

    # Audit users
    print("\nUSERS")
    print("-" * 60)
    users = list_users(iam)
    for user in users:
        username = user['UserName']
        all_findings = []
        for policy in get_user_policies(iam, username):
            all_findings.extend(analyze_policy(policy))
        print_findings('User', username, all_findings)

    # Audit roles
    print("\n\nROLES")
    print("-" * 60)
    roles = list_roles(iam)
    for role in roles:
        role_name = role['RoleName']
        all_findings = []
        for policy in get_role_policies(iam, role_name):
            all_findings.extend(analyze_policy(policy))
        print_findings('Role', role_name, all_findings)

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()