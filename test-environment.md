# Test Environment

This document describes the deliberately misconfigured IAM resources created
to validate the auditor's detection capabilities.

## Resources

| Resource | Type | Misconfiguration | Expected Finding |
|---|---|---|---|
| `dev-user-bad` | IAM User | AdministratorAccess attached | HIGH: Wildcard permissions (*:*) |
| `s3-fullaccess-role` | IAM Role | AmazonS3FullAccess attached | MEDIUM: Service-level wildcard (s3:*) |
| `legacy-unused-role` | IAM Role | Never assumed | LOW: Unused role detection |
| `ec2-overprivileged-role` | IAM Role | ec2:* + iam:PassRole/CreateRole | HIGH: Privilege escalation path |

## Cleanup

To remove these resources after testing, see `cleanup.md` (added in Day 7).