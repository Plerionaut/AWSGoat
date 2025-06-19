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

resource "aws_lambda_function" "react_lambda_app" {
  filename      = "resources/lambda/out/reactapp.zip"
  function_name = "blog-application"
  handler       = "index.handler"
  runtime       = "nodejs18.x"
  role          = aws_iam_role.blog_app_lambda.arn
  depends_on    = [data.archive_file.lambda_zip, null_resource.file_replacement_lambda_react]
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
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}
resource "aws_iam_role_policy_attachment" "ba_lambda_attach_3" {
  role       = aws_iam_role.blog_app_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonAPIGatewayInvokeFullAccess"
}


resource "aws_api_gateway_rest_api" "api" {
  name = "blog-application"
  endpoint_configuration {
    types = [
      "REGIONAL"
    ]
  }
}


resource "aws_api_gateway_resource" "endpoint" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "react"
}

resource "aws_api_gateway_method" "endpoint" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.endpoint.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_method_response" "endpoint" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.endpoint.id
  http_method = aws_api_gateway_method.endpoint.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
  response_models = {
    "application/json" = "Empty"
  }

}

resource "aws_api_gateway_integration" "endpoint" {
  depends_on = [aws_api_gateway_method.endpoint, aws_api_gateway_method_response.endpoint]

  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_method.endpoint.resource_id
  http_method             = aws_api_gateway_method.endpoint.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.react_lambda_app.invoke_arn
  request_templates = {
    "application/json" = jsonencode(
      {
        statusCode = 200
      }
    )
  }
}

resource "aws_api_gateway_integration_response" "endpoint" {
  depends_on = [aws_api_gateway_integration.endpoint]

  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = aws_api_gateway_resource.endpoint.id
  http_method = aws_api_gateway_method.endpoint.http_method
  status_code = aws_api_gateway_method_response.endpoint.status_code

  response_templates = {
    "text/html" = ""
  }
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,JWT_TOKEN'",
    "method.response.header.Access-Control-Allow-Methods" = "'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT'",
    "method.response.header.Access-Control-Allow-Origin"  = "'*'",
  }
}

resource "aws_lambda_permission" "apigw_ba" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.react_lambda_app.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}




resource "aws_api_gateway_deployment" "api" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  description = "Deployed endpoint at ${timestamp()}"
  depends_on  = [aws_api_gateway_integration_response.endpoint]
}

resource "aws_api_gateway_stage" "api" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.api.id
}




/* API Gateway -- REST API lambda_ba */


resource "aws_api_gateway_rest_api" "apiLambda_ba" {
  name           = "blog-application-api"
  api_key_source = "HEADER"
  endpoint_configuration {
    types = [
      "REGIONAL"
    ]
  }
}


/* API ENDPOINTS */

# XSS
#########################################################################################################################
resource "aws_api_gateway_resource" "xss_root" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda_ba.id
  parent_id   = aws_api_gateway_rest_api.apiLambda_ba.root_resource_id
  path_part   = "xss"
}
resource "aws_api_gateway_method" "proxy_xss_root_post" {
  rest_api_id   = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id   = aws_api_gateway_resource.xss_root.id
  http_method   = "POST"
  authorization = "NONE"
}
resource "aws_api_gateway_method_response" "proxy_xss_root_post_response_200" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id = aws_api_gateway_resource.xss_root.id
  http_method = aws_api_gateway_method.proxy_xss_root_post.http_method
  status_code = 200

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_method" "xss_root_options" {
  rest_api_id        = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id        = aws_api_gateway_resource.xss_root.id
  http_method        = "OPTIONS"
  authorization      = "NONE"
  request_parameters = { "method.request.header.JWT_TOKEN" = false }

}
resource "aws_api_gateway_method_response" "xss_root_options_response_200" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id = aws_api_gateway_resource.xss_root.id
  http_method = aws_api_gateway_method.xss_root_options.http_method
  status_code = 200

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers"     = true,
    "method.response.header.Access-Control-Allow-Methods"     = true,
    "method.response.header.Access-Control-Allow-Origin"      = true,
    "method.response.header.Access-Control-Allow-Credentials" = true
  }
  response_models = {
    "application/json" = "Empty"
  }
}

resource "aws_api_gateway_integration" "lambda_xss_root_post" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id = aws_api_gateway_resource.xss_root.id
  http_method = aws_api_gateway_method.proxy_xss_root_post.http_method

  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.lambda_ba_data.invoke_arn
  request_templates = {
    "application/json" = jsonencode(
      {
        statusCode = 200
      }
    )
  }
}

resource "aws_api_gateway_integration_response" "lambda_xss_root_post_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id = aws_api_gateway_resource.xss_root.id
  http_method = aws_api_gateway_method.proxy_xss_root_post.http_method
  status_code = aws_api_gateway_method_response.proxy_xss_root_post_response_200.status_code


  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token,JWT_TOKEN'",
    "method.response.header.Access-Control-Allow-Methods" = "'DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT'",
    "method.response.header.Access-Control-Allow-Origin"  = "'*'",

  }

  depends_on = [aws_api_gateway_integration.lambda_xss_root_post, aws_api_gateway_method_response.proxy_xss_root_post_response_200]
}

resource "aws_api_gateway_integration" "lambda_xss_root_options" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda_ba.id
  resource_id = aws_api_gateway_resource.xss_root.id
  http_method = aws_api_gateway_method.xss_root_options.http_method


  type                 = "MOCK"
  passthrough_behavior = "WHEN_NO_MATCH"

  request_templates = {
    "application/json" = jsonencode(
      {
        statusCode = 200
      }
    )
  }
}
resource "aws_api_gateway_integration_response" "lambda_xss_root_options_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.apiLambda