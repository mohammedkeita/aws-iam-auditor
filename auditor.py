"""
AWS IAM Least-Privilege Auditor
A tool to scan AWS IAM users and roles for over-permissioned policies.
"""

import boto3


def get_iam_client():
    """Return a boto3 IAM client."""
    return boto3.client('iam')


def list_users(iam):
    """Return a list of all IAM users in the account."""
    users = []
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        users.extend(page['Users'])
    return users


def get_user_policies(iam, username):
    """Return all policies attached to a user."""
    attached = iam.list_attached_user_policies(UserName=username)
    managed = [
        {'name': p['PolicyName'], 'arn': p['PolicyArn']}
        for p in attached['AttachedPolicies']
    ]

    inline_names = iam.list_user_policies(UserName=username)['PolicyNames']
    inline = []
    for name in inline_names:
        doc = iam.get_user_policy(UserName=username, PolicyName=name)
        inline.append({'name': name, 'document': doc['PolicyDocument']})

    return {'managed': managed, 'inline': inline}


def list_roles(iam):
    """Return a list of all IAM roles in the account."""
    roles = []
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        roles.extend(page['Roles'])
    return roles


def get_role_policies(iam, role_name):
    """Return all policies attached to a role."""
    attached = iam.list_attached_role_policies(RoleName=role_name)
    managed = [
        {'name': p['PolicyName'], 'arn': p['PolicyArn']}
        for p in attached['AttachedPolicies']
    ]

    inline_names = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    inline = []
    for name in inline_names:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=name)
        inline.append({'name': name, 'document': doc['PolicyDocument']})

    return {'managed': managed, 'inline': inline}


def main():
    iam = get_iam_client()

    # USERS
    users = list_users(iam)
    print(f"Found {len(users)} IAM user(s):\n")
    for user in users:
        username = user['UserName']
        policies = get_user_policies(iam, username)
        print(f"  • {username}")
        for p in policies['managed']:
            print(f"      [managed] {p['name']}")
        for p in policies['inline']:
            print(f"      [inline]  {p['name']}")
        if not policies['managed'] and not policies['inline']:
            print(f"      (no policies)")

    print()

    # ROLES
    roles = list_roles(iam)
    user_roles = [r for r in roles if not r['RoleName'].startswith('AWSServiceRoleFor')]

    print(f"Found {len(user_roles)} IAM role(s) (excluding service-linked):\n")
    for role in user_roles:
        role_name = role['RoleName']
        policies = get_role_policies(iam, role_name)
        print(f"  • {role_name}")
        for p in policies['managed']:
            print(f"      [managed] {p['name']}")
        for p in policies['inline']:
            print(f"      [inline]  {p['name']}")
        if not policies['managed'] and not policies['inline']:
            print(f"      (no policies)")


if __name__ == "__main__":
    main()