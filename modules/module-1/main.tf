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

# KMS keys for encryption
resource "aws_kms_key" "lambda_key" {
  description             = "KMS key for Lambda encryption"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "lambda_key_alias" {
  name          = "alias/lambda-encryption-key"
  target_key_id = aws_kms_key.lambda_