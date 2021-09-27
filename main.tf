#-----------------------------------------------------------------------------------------------------------------------
# Subscribe the Acccount to GuardDuty
#-----------------------------------------------------------------------------------------------------------------------
resource "aws_guardduty_detector" "guardduty" {
  enable                       = module.this.enabled
  finding_publishing_frequency = var.finding_publishing_frequency
}

#-----------------------------------------------------------------------------------------------------------------------
# Optionally configure Event Bridge Rules and SNS subscriptions 
# https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cwe-integration-types.html
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/resource-based-policies-cwe.html#sns-permissions
#-----------------------------------------------------------------------------------------------------------------------
module "sns_topic" {

  source = "git::https://github.com/logicnow/terraform-aws-sns-topic.git"
  count  = local.create_sns_topic ? 1 : 0

  subscribers     = var.subscribers
  sqs_dlq_enabled = false

  attributes = concat(module.this.attributes, ["guardduty"])
  context    = module.this.context

  kms_encryption_enabled = var.sns_kms_enabled
}

module "findings_label" {
  source  = "cloudposse/label/null"
  version = "0.24.1"

  attributes = concat(module.this.attributes, ["guardduty", "findings"])
  context    = module.this.context
}

resource "aws_sns_topic_policy" "sns_topic_publish_policy" {
  depends_on = [module.sns_topic]
  count      = module.this.enabled && local.create_sns_topic ? 1 : 0
  policy     = data.aws_iam_policy_document.sns_topic_policy[0].json
  arn        = module.sns_topic[0].sns_topic.arn
}

data "aws_iam_policy_document" "sns_topic_policy" {
  count     = module.this.enabled && local.create_sns_topic ? 1 : 0
  policy_id = "GuardDutyPublishToSNS"
  statement {
    sid = ""
    actions = [
      "sns:Publish"
    ]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "lambda.amazonaws.com"]
    }
    resources = [module.sns_topic[0].sns_topic.arn]
    effect    = "Allow"
  }
}

resource "aws_cloudwatch_event_rule" "findings" {
  count       = local.enable_notifications == true ? 1 : 0
  name        = module.findings_label.id
  description = "GuardDuty Findings"
  tags        = module.this.tags

  event_pattern = jsonencode(
    {
      "source" : [
        "aws.guardduty"
      ],
      "detail-type" : [
        var.cloudwatch_event_rule_pattern_detail_type
      ]
    }
  )
}

resource "aws_cloudwatch_event_target" "imported_findings" {
  count = local.enable_notifications == true ? 1 : 0
  rule  = aws_cloudwatch_event_rule.findings[0].name
  arn   = local.findings_notification_arn
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda_${terraform.workspace}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_policy" "lambda_to_sns" {

  name        = "iam_policy_lambda_publish_to_guardduty_sns_${terraform.workspace}"
  path        = "/"
  description = "IAM policy for publishing to the SNS for GuardDuty"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "sns:Publish"
      ],
      "Resource": "${module.sns_topic[0].sns_topic.arn}",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_to_sns_policy_attach" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_to_sns.arn
}

resource "aws_iam_policy" "lambda_logging" {

  name        = "iam_policy_lambda_logging_function_${terraform.workspace}"
  path        = "/"
  description = "IAM policy for logging from a lambda"
  policy      = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_logging_policy_attach" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.lambda_logging.arn
}

resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty-severity-transform.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.findings[0].arn
}

data "archive_file" "lambda_function_payload" {
  type        = "zip"
  source_dir  = "${path.module}/guardduty-severity-transform/"
  output_path = "${path.module}/lambda_function_payload.zip"
}

resource "aws_lambda_function" "guardduty-severity-transform" {
  depends_on    = [data.archive_file.lambda_function_payload]
  tags          = module.this.tags
  filename      = "lambda_function_payload.zip"
  function_name = "guardduty-severity-transform"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"
  #source_code_hash = filebase64sha256("lambda_function_payload.zip")
  runtime = "nodejs14.x"

  environment {
    variables = {
      topic_arn = module.sns_topic[0].sns_topic.arn
    }
  }
}


#-----------------------------------------------------------------------------------------------------------------------
# Locals and Data References
#-----------------------------------------------------------------------------------------------------------------------
locals {
  enable_notifications      = module.this.enabled && (var.create_sns_topic || var.findings_notification_arn != null)
  create_sns_topic          = module.this.enabled && var.create_sns_topic
  findings_notification_arn = local.enable_notifications ? (var.findings_notification_arn != null ? var.findings_notification_arn : aws_lambda_function.guardduty-severity-transform.arn) : null
}
