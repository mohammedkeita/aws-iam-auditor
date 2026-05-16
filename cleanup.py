"""
Cleanup script for the IAM auditor test environment.

Removes the deliberately misconfigured IAM resources created for testing:
- dev-user-bad
- s3-fullaccess-role
- legacy-unused-role
- ec2-overprivileged-role (and its custom policy)

Usage:
    python cleanup.py            # dry run (default — shows what would be deleted)
    python cleanup.py --confirm  # actually delete the resources
"""

import argparse
import sys

import boto3
from botocore.exceptions import ClientError


TEST_USERS = ['dev-user-bad']
TEST_ROLES = [
    's3-fullaccess-role',
    'legacy-unused-role',
    'ec2-overprivileged-role',
]
TEST_POLICIES = ['ec2-overprivileged-policy']


def detach_and_delete_user(iam, username, dry_run):
    print(f"User: {username}")
    try:
        attached = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        for p in attached:
            print(f"  - detach policy {p['PolicyName']}")
            if not dry_run:
                iam.detach_user_policy(UserName=username, PolicyArn=p['PolicyArn'])

        inline = iam.list_user_policies(UserName=username)['PolicyNames']
        for name in inline:
            print(f"  - delete inline policy {name}")
            if not dry_run:
                iam.delete_user_policy(UserName=username, PolicyName=name)

        print(f"  - delete user")
        if not dry_run:
            iam.delete_user(UserName=username)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"  (not found, skipping)")
        else:
            raise


def detach_and_delete_role(iam, role_name, dry_run):
    print(f"Role: {role_name}")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        for p in attached:
            print(f"  - detach policy {p['PolicyName']}")
            if not dry_run:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=p['PolicyArn'])

        inline = iam.list_role_policies(RoleName=role_name)['PolicyNames']
        for name in inline:
            print(f"  - delete inline policy {name}")
            if not dry_run:
                iam.delete_role_policy(RoleName=role_name, PolicyName=name)

        print(f"  - delete role")
        if not dry_run:
            iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"  (not found, skipping)")
        else:
            raise


def delete_custom_policy(iam, policy_name, account_id, dry_run):
    arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
    print(f"Policy: {policy_name}")
    try:
        # All non-default versions must be deleted before the policy itself
        versions = iam.list_policy_versions(PolicyArn=arn)['Versions']
        for v in versions:
            if not v['IsDefaultVersion']:
                print(f"  - delete version {v['VersionId']}")
                if not dry_run:
                    iam.delete_policy_version(PolicyArn=arn, VersionId=v['VersionId'])

        print(f"  - delete policy")
        if not dry_run:
            iam.delete_policy(PolicyArn=arn)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"  (not found, skipping)")
        else:
            raise


def main():
    parser = argparse.ArgumentParser(description='Clean up the IAM auditor test environment.')
    parser.add_argument('--confirm', action='store_true',
                        help='Actually perform deletions (without this, runs in dry-run mode)')
    args = parser.parse_args()

    dry_run = not args.confirm
    iam = boto3.client('iam')
    account_id = boto3.client('sts').get_caller_identity()['Account']

    if dry_run:
        print("=== DRY RUN — no resources will be deleted ===")
        print("Re-run with --confirm to actually delete.\n")
    else:
        print("=== LIVE RUN — resources will be deleted ===\n")

    for username in TEST_USERS:
        detach_and_delete_user(iam, username, dry_run)
        print()

    for role_name in TEST_ROLES:
        detach_and_delete_role(iam, role_name, dry_run)
        print()

    for policy_name in TEST_POLICIES:
        delete_custom_policy(iam, policy_name, account_id, dry_run)
        print()

    print("Done.")


if __name__ == "__main__":
    main()