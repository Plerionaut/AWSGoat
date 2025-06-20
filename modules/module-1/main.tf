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

resource "aws_kms_key" "lambda_key" {
  description             = "KMS key for Lambda encryption"
  deletion_window_in_days = 7
}

resource "aws_kms_key" "dlq_key" {
  description             = "KMS key for DLQ encryption"
  deletion_window_in_days = 7
}

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "lambda-dlq"
  kms_master_key_id         = aws_kms_key.dlq_key.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_vpc" "lambda_vpc" {
  cidr_block           = "10.0.0.