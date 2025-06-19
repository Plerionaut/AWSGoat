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

resource "aws_internet_gateway" "lambda_igw" {
  vpc_id = aws_vpc.lambda_vpc.id

  tags = {
    Name = "lambda-igw"
  }
}

resource "aws_route_table" "lambda_rt" {
  vpc_id = aws_vpc.lambda_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lambda_igw.id
  }

  tags = {
    Name = "lambda-rt"
  }
}

resource "aws_route_table_association" "lambda_rta_1" {
  subnet_id      = aws_subnet.lambda_subnet_1.id
  route_table_id = aws_route_table.lambda_rt.id
}

resource "aws_route_table_association" "lambda_rta_2" {
  subnet_id      = aws_subnet.lambda_subnet_2.id
  route_table_id = aws_route_table.lambda_rt.id
}

resource "aws_security_group" "lambda_sg" {
  name        = "lambda-sg"
  description = "Security group for Lambda functions"
  vpc_id      = aws_vpc.lambda_vpc.id

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "lambda-sg"
  }
}

# KMS key for Lambda environment variables
resource "aws_kms_key" "lambda_env_key" {
  description             = "KMS key for Lambda environment variables"
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "lambda_env_key_alias" {
  name          = "alias/lambda-env-key"
  target_key_id = aws_kms_key.lambda_env_key.key_id
}

# SQS DLQ for Lambda functions
resource "aws_sqs_queue" "lambda_dlq" {
  name = "lambda-dlq"
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "resources/lambda/react"
  output_path = "resources/lambda/out/reactapp.zip"
  depends_on  = [aws_s3_object.upload_folder_prod]
}

resource "aws_lambda_function" "react_lambda_app" {
  filename         = "resources/lambda/out/reactapp.zip"
  function_name    = "blog-application"
  handler          = "index