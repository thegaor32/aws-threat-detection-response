import json
import os
import time
from datetime import datetime, timezone

import boto3

ec2 = boto3.client("ec2")
iam = boto3.client("iam")
sns = boto3.client("sns")

QUARANTINE_SG = os.environ["QUARANTINE_SG_ID"]
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]


def contain_instance(instance_id, finding_id):
    """Isolate the instance, tag it, and take forensic snapshots."""
    actions = []
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    old_sgs = [g["GroupId"] for g in inst["SecurityGroups"]]

    # 1. Isolate first: most important step
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[QUARANTINE_SG])
    actions.append(f"Isolated {instance_id}: {old_sgs} -> {QUARANTINE_SG}")

    # 2. Tag it so everyone knows it's quarantined
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "tdr-status", "Value": "quarantined"}])
    actions.append("Tagged tdr-status=quarantined")

    # 3. Snapshot each disk; one failure doesn't stop the rest
    for mapping in inst.get("BlockDeviceMappings", []):
        volume_id = mapping["Ebs"]["VolumeId"]
        try:
            snap = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"Forensic snapshot for GuardDuty finding {finding_id}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": "tdr-finding", "Value": finding_id}],
                }],
            )
            actions.append(f"Snapshot {snap['SnapshotId']} of {volume_id}")
        except Exception as err:
            actions.append(f"Snapshot of {volume_id} failed: {err}")
    return actions


def disable_access_key(user_name, key_id):
    iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status="Inactive")
    return [f"Disabled access key {key_id} for user {user_name}"]


def lambda_handler(event, context):
    started = time.time()
    detail = event["detail"]
    finding_id = detail["id"]
    finding_type = detail["type"]
    resource = detail["resource"]

    # Ignore GuardDuty's practice findings; they point at fake resources
    if detail.get("service", {}).get("additionalInfo", {}).get("sample"):
        print(f"Skipping sample finding {finding_type}")
        return {"skipped": True}

    actions = []
    try:
        if resource["resourceType"] == "Instance":
            actions += contain_instance(resource["instanceDetails"]["instanceId"], finding_id)
        elif resource["resourceType"] == "AccessKey":
            key = resource["accessKeyDetails"]
            actions += disable_access_key(key["userName"], key["accessKeyId"])
        else:
            actions.append(f"No automatic action for resource type {resource['resourceType']}")
    except Exception as err:  # still alert a human if containment fails
        actions.append(f"ERROR during containment: {err}")

    # Repeat findings keep their old createdAt, so time from the latest update
    finding_time = detail.get("updatedAt") or detail["createdAt"]
    found_at = datetime.fromisoformat(finding_time.replace("Z", "+00:00"))
    report = {
        "finding_type": finding_type,
        "severity": detail["severity"],
        "finding_id": finding_id,
        "actions_taken": actions,
        "lambda_runtime_seconds": round(time.time() - started, 2),
        "seconds_from_finding_to_containment": round(
            (datetime.now(timezone.utc) - found_at).total_seconds(), 1
        ),
    }
    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject=f"[GuardDuty] {finding_type}"[:100],
        Message=json.dumps(report, indent=2),
    )
    print(json.dumps(report))  # shows up in CloudWatch Logs for the dashboard
    return report
