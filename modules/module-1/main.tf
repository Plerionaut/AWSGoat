terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.24.0"
    }
  }
}
provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "resources/lambda/react"
  output_path = "resources/lambda/out/reactapp.zip"
  depends_on  = [aws_s3_object.upload_folder_prod]
}

# VPC for Lambda functions
resource "aws_vpc" "lambda_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "lambda-vpc"
  }
}

resource "aws_subnet" "lambda_subnet_1" {
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = {
    Name = "lambda-subnet-1"
  }
}

resource "aws_subnet" "lambda_subnet_2" {
  vpc_id                  = aws_vpc.lambda_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false

  tags = {
    Name = "lambda-subnet-2"
  }
}

resource "aws_security_group" "lambda_sg" {
  name_prefix = "lambda-sg"
  vpc_id      = aws_vpc.lambda_vpc.id

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lambda-security-group"
  }
}

# KMS Key for Lambda environment variables
resource "aws_kms_key" "lambda_env_key" {
  description = "KMS key for Lambda environment variables"
}

resource "aws_kms_alias" "lambda_env_key_alias" {
  name          = "alias/lambda-env-key"
  target_key_id = aws_kms_key.lambda_env_key.key_id
}

# Dead Letter Queue for Lambda
resource "aws_sqs_queue" "lambda_dlq" {
  name = "lambda-dlq"
}

resource "aws_lambda_function" "react_lambda_app" {
  filename         = "resources/lambda/out/reactapp.zip"
  function_name    = "blog-application"
  handler          = "index.handler"
  runtime          = "nodejs18.x"
  role             = aws_iam_role.blog_app_lambda.arn
  depends_on       = [data.archive_file.lambda_zip, null_resource.file_replacement_lambda_react]
  reserved_concurrent_executions = 10

  vpc_config {
    subnet_ids         = [aws_subnet.lambda_subnet_1.id, aws_subnet.lambda_subnet_2.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      NODE_ENV = "production"
    }
    kms_key_arn = aws_kms_key.lambda_env_key.arn
  }

  code_signing_config_arn = aws_lambda_code_signing_config.lambda_csc.arn
}

# Code signing configuration
resource "aws_signer_signing_profile" "lambda_signing_profile" {
  platform_id = "AWSLambda-SHA384-ECDSA"
  name        = "lambda_signing_profile"
}

resource "aws_lambda_code_signing_config" "lambda_csc" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.lambda_signing_profile.arn]
  }

  policies {
    untrusted_artifact_on_deployment = "Warn"
  }

  description = "Code signing config for Lambda functions"
}

/* Lambda iam Role */
resource "aws_iam_role" "blog_app_lambda" {
  name = "blog_app_lambda"

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

resource "aws_iam_role_policy_attachment" "ba_lambda_attach_2" {
  role       = aws_iam_role.blog_app_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "ba_lambda_attach_3" {
  role       = aws_iam_role.blog_app_lambda.name
  policy_arn = aws_iam_policy.lambda_limited_policy.arn
}

resource "aws_iam_policy" "lambda_limited_policy" {
  name = "lambda-limited-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs