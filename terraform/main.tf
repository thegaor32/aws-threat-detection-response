terraform {
  required_version = ">= 1.10"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 6.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
  }
  backend "s3" {
    bucket       = "tdr-tfstate-492698501523"
    key          = "threat-detection/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC where the test instance runs"
}

variable "alert_email" {
  type        = string
  description = "Where security alerts are emailed"
}

data "aws_caller_identity" "current" {}

# --- Alerting ---
resource "aws_sns_topic" "alerts" {
  name              = "tdr-alerts"
  kms_master_key_id = "alias/aws/sns" # Checkov CKV_AWS_26: encrypt alerts at rest
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Quarantine security group: no inbound, no outbound ---
resource "aws_security_group" "quarantine" {
  name        = "tdr-quarantine-sg"
  description = "Isolates compromised instances - no traffic in or out"
  vpc_id      = var.vpc_id
}

# --- Lambda permissions ---
resource "aws_iam_role" "lambda" {
  name = "tdr-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "response_actions" {
  name = "tdr-response-actions"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadInstances"
        Effect   = "Allow"
        Action   = "ec2:DescribeInstances" # read-only; AWS does not support resource scoping here
        Resource = "*"
      },
      {
        Sid    = "IsolateInstance"
        Effect = "Allow"
        Action = "ec2:ModifyInstanceAttribute"
        Resource = [
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:security-group/*"
        ]
      },
      {
        Sid    = "ForensicSnapshot"
        Effect = "Allow"
        Action = "ec2:CreateSnapshot"
        Resource = [
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:volume/*",
          "arn:aws:ec2:${var.region}::snapshot/*"
        ]
      },
      {
        Sid    = "TagEvidence"
        Effect = "Allow"
        Action = "ec2:CreateTags"
        Resource = [
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ec2:${var.region}::snapshot/*"
        ]
      },
      {
        Sid      = "DisableKeys"
        Effect   = "Allow"
        Action   = "iam:UpdateAccessKey"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"
      },
      {
        Sid      = "Alert"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.alerts.arn
      }
    ]
  })
}

# --- The responder Lambda ---
data "archive_file" "lambda" {
  type        = "zip"
  source_file = "${path.module}/../lambda/lambda_function.py"
  output_path = "${path.module}/build/lambda.zip"
}

resource "aws_cloudwatch_log_group" "lambda" {
  #checkov:skip=CKV_AWS_158:Logs hold no secrets; a customer-managed KMS key adds cost for a lab
  name              = "/aws/lambda/tdr-responder"
  retention_in_days = 365 # Checkov CKV_AWS_338: keep incident logs for 1 year
}

resource "aws_lambda_function" "responder" {
  #checkov:skip=CKV_AWS_117:Only calls AWS APIs, no private VPC resources to reach
  #checkov:skip=CKV_AWS_116:Errors are caught in code and still alert a human through SNS
  #checkov:skip=CKV_AWS_115:New account concurrency quota is too low to reserve capacity
  #checkov:skip=CKV_AWS_272:Single-developer lab; code is reviewed and deployed only by the pipeline
  #checkov:skip=CKV_AWS_173:Environment variables hold only IDs (security group, topic ARN), no secrets
  function_name    = "tdr-responder"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  environment {
    variables = {
      QUARANTINE_SG_ID = aws_security_group.quarantine.id
      SNS_TOPIC_ARN    = aws_sns_topic.alerts.arn
    }
  }

  tracing_config {
    mode = "Active" # Checkov CKV_AWS_50: X-Ray tracing for every response
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy_attachment.xray]
}

# --- GuardDuty finding -> Lambda ---
resource "aws_cloudwatch_event_rule" "guardduty" {
  name = "tdr-guardduty-high"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = { severity = [{ numeric = [">=", 4] }] }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.guardduty.name
  arn  = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty.arn
}
