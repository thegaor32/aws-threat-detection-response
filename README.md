# Automated Threat Detection & Response on AWS

When an attacker gets into a cloud server, the gap between the alert and a human reacting is where the damage happens. This project closes that gap: when Amazon GuardDuty detects a threat, a Python Lambda function contains it automatically in seconds and emails a report.

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
   Amazon SNS  --> email report to responder
   CloudWatch Logs + Dashboard  --> history of every response
```

Also enabled: AWS CloudTrail (API audit log) and AWS Security Hub (central findings view).

## What it does

| Threat | Automatic action |
|---|---|
| Compromised EC2 instance | Isolates it with a no-rules quarantine security group, tags it, and snapshots its disks for forensics |
| Leaked IAM access key | Sets the key to Inactive |
| Anything else (severity 4+) | Sends the alert to a human |

Every response is emailed through SNS and logged to CloudWatch. If a containment step fails, the function records the error and still sends the alert, so a human is never left in the dark.

## Results

| Measurement | Result |
|---|---|
| Manual containment (following the same runbook by hand in the console) | **3 min 4 s** |
| Automated containment of a real GuardDuty finding (finding created to instance isolated) | **10.3 s** |
| Real finding type triggered and contained | `Backdoor:EC2/C&CActivity.B!DNS` (High, severity 8) |
| Lambda runtime for full containment (isolate + tag + snapshot) | ~1.5 s |

The attack was simulated safely on my own test instance by resolving GuardDuty's official test domain (`guarddutyc2activityb.com`). The access-key path was verified with a Lambda test event.

## What I learned / fixed

On the first real run, the EBS snapshot call was rejected by an AWS rate limit (`SnapshotCreationPerVolumeRateExceeded`). The instance was still isolated, but the remaining steps were skipped. I reordered the function so isolation and tagging happen first, and wrapped each snapshot in its own error handling so one failed step can't stop the others.

## Screenshots

See `docs/screenshots/`: alert email, quarantined instance, forensic snapshot, deactivated key, CloudWatch dashboard.

## What I'd add next

- Slack or Microsoft Teams alerts instead of email
- Terraform + GitHub Actions to deploy everything as code, with a Checkov security scan
- Automatic release from quarantine after an analyst approves

## Tech

Amazon GuardDuty, Amazon EventBridge, AWS Lambda (Python 3.12, boto3), Amazon SNS, Amazon EC2, Amazon EBS, AWS IAM, AWS CloudTrail, AWS Security Hub, Amazon CloudWatch
