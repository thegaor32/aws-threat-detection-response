# Automated Threat Detection & Response on AWS

When an attacker gets into a cloud server, the gap between the alert and a human reacting is where the damage happens. This project closes that gap: when Amazon GuardDuty detects a threat, a Python Lambda function contains it automatically in seconds and emails a report. Everything is deployed as code with Terraform through a GitHub Actions pipeline that runs a Checkov security scan first.

## Architecture

```
 Attack on EC2 / leaked key
            |
            v
   Amazon GuardDuty  (detects threat, creates finding)
            |
            v
   Amazon EventBridge  (rule: severity >= 4)
            |
            v
   AWS Lambda "tdr-responder" (Python)
     |-- EC2: swap to quarantine security group (no traffic in/out)
     |-- EC2: tag instance tdr-status=quarantined
     |-- EC2: snapshot EBS volumes for forensics
     |-- IAM: deactivate the leaked access key
     v
   Amazon SNS (encrypted)  --> email report to responder
   CloudWatch Logs + Dashboard + X-Ray  --> history of every response

 GitHub push --> GitHub Actions: Checkov scan --> OIDC login to AWS (no stored keys) --> terraform apply
```

Also enabled: AWS CloudTrail (API audit log) and AWS Security Hub (central findings view).

## What it does

| Threat | Automatic action |
|---|---|
| Compromised EC2 instance | Isolates it with a no-rules quarantine security group, tags it, and snapshots its disks for forensics |
| Leaked IAM access key | Sets the key to Inactive |
| Anything else (severity 4+) | Sends the alert to a human |

Every response is emailed through SNS and logged to CloudWatch. Each containment step is independent: if one fails, the function records the error, keeps going, and still alerts a human.

## Results

| Measurement | Result |
|---|---|
| Manual containment (same runbook by hand in the console) | **3 min 4 s** |
| Automated containment of a real, new GuardDuty finding (finding created to instance isolated) | **10.3 s** |
| Real finding type triggered and contained | `Backdoor:EC2/C&CActivity.B!DNS` (High, severity 8), contained on 3 separate runs |
| Lambda runtime for full containment (isolate + tag + snapshot) | ~1.5 to 1.7 s |
| Resources deployed with Terraform | **12** |
| Checkov scan | **11 failed → 0 failed** (5 fixed, 6 skipped with documented reasons; 35 passed) |

The attack was simulated safely on my own test instance by resolving GuardDuty's official test domain (`guarddutyc2activityb.com`). The access-key path was verified with a Lambda test event.

Note on timing: 10.3 s is measured for a *new* finding. Repeat occurrences of the same finding are batched by GuardDuty and published every 15 minutes (the fastest setting), so they reach the Lambda later; the Lambda itself still finishes in under 2 seconds.

## Security hardening (Checkov)

Fixed:
- SNS alert topic encrypted with KMS
- Lambda log retention raised from 30 days to 1 year
- X-Ray tracing enabled on the Lambda
- Lambda IAM policy narrowed from `"*"` to only this account's instances, volumes, snapshots and security groups (least privilege)

Skipped, with the reason written next to each in `terraform/main.tf`: Lambda in a VPC (only calls AWS APIs), dead-letter queue (errors already alert a human), reserved concurrency (new-account quota), code signing, env-var KMS (no secrets in env vars), log-group customer KMS key (cost for a lab).

## What I learned / fixed

1. **AWS rate limit on the first real run.** The EBS snapshot call was rejected (`SnapshotCreationPerVolumeRateExceeded`). The instance was still isolated, but later steps were skipped. I reordered the function so isolation and tagging happen first and wrapped each snapshot in its own error handling.
2. **GitHub OIDC login denied.** The deploy job failed with `Not authorized to perform sts:AssumeRoleWithWebIdentity`. Using CloudTrail, I found GitHub now sends a subject with immutable IDs (`repo:owner@id/repo@id:ref:refs/heads/main`), which the console-generated trust policy didn't match. I rewrote the trust policy to match that exact subject, locked to this repo's `main` branch.
3. **Repeat findings are batched.** Timing a repeat finding gave ~11 minutes; that was GuardDuty's publishing interval, not the Lambda. I measure response time on new findings and report the batching separately.

## How to deploy

```
cd terraform
terraform init
terraform apply -var="vpc_id=vpc-xxxx" -var="alert_email=you@example.com"
```

Or push to `main`: GitHub Actions runs Checkov, then deploys with a short-lived OIDC role (no AWS keys stored in GitHub).

## What I'd add next

- Slack or Microsoft Teams alerts instead of email
- Automatic release from quarantine after an analyst approves
- A narrower IAM policy for the GitHub deploy role (currently AdministratorAccess for the lab)

## Tech

Amazon GuardDuty, Amazon EventBridge, AWS Lambda (Python 3.12, boto3), Amazon SNS, Amazon EC2, Amazon EBS, AWS IAM, AWS CloudTrail, AWS Security Hub, Amazon CloudWatch, AWS X-Ray, Terraform, GitHub Actions (OIDC), Checkov
