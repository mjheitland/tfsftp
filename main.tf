############################################
#              TOOL CONFIG                 #
############################################

terraform {
  required_version = ">= 0.12"
  required_providers {
    aws = ">= 2.60.0"
  }
#  backend "s3" {
#    key    = "a2l/customer-parameters/terraform.tfstate"
#    region = "eu-west-1"
#  }
}

# Precondition:
#   export AWS_DEFAULT_REGION=eu-west-1

provider "aws" {
#  assume_role {
#    role_arn     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aztecaut-itmasterplatform-prod-infraadmin-assumerole"
#    session_name = "terraform-deploy-parameter-store"
#  }
  profile = "default"
  region  = var.region
}

data "aws_caller_identity" "current" {}

variable "region" {
  description = "AWS region we are deploying to"
  type        = string
  default     = "eu-west-1"
}

variable "sftp_parameter_prefix" {
  description = "S3 key prefix used for all SFTP files"
  type        = string
  default     = "/SFTP/"
}

locals {
  sftp_bucket = "sftp-bucket-${data.aws_caller_identity.current.account_id}"
}


#-------------
#--- Resources
#-------------

############################################
#               SFTP Bucket                #
############################################
resource "aws_s3_bucket" "sftp_bucket" {
  bucket = local.sftp_bucket

  # The canned ACL to apply. Defaults to "private". Conflicts with grant.
  # "private": Owner gets FULL_CONTROL. No one else has access rights (default).
  acl = "private"

  # A boolean that indicates all objects (including any locked objects) should be deleted from the bucket
  # so that the bucket can be destroyed without error. These objects are not recoverable.
  force_destroy = true

  # prevent accidental deletion of this bucket
  # (if you really have to destroy this bucket, change this value to false and reapply, then run destroy)
  lifecycle {
    prevent_destroy = false
  }

  # enable versioning so we can see the full revision history of our state file
  versioning {
    enabled = false
  }

  # enable server-side encryption by default
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        # kms_master_key_id = aws_kms_key.ROOT-KMS-S3.arn
        # sse_algorithm     = "aws:kms"
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "sftp_bucket_block_public_access" {
  bucket = aws_s3_bucket.sftp_bucket.id

  # Whether Amazon S3 should block public bucket policies for this bucket. Defaults to false.
  # Enabling this setting does not affect the existing bucket policy. When set to true causes Amazon S3 to:
  # Reject calls to PUT Bucket policy if the specified bucket policy allows public access.
  block_public_acls       = true

  # Whether Amazon S3 should block public bucket policies for this bucket. Defaults to false.
  # Enabling this setting does not affect the existing bucket policy. When set to true causes Amazon S3 to:
  # Reject calls to PUT Bucket policy if the specified bucket policy allows public access.
  block_public_policy     = true

  # Whether Amazon S3 should ignore public ACLs for this bucket. Defaults to false.
  # Enabling this setting does not affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set. When set to true causes Amazon S3 to:
  # Ignore public ACLs on this bucket and any objects that it contains.
  ignore_public_acls      = true

  # Whether Amazon S3 should restrict public bucket policies for this bucket. Defaults to false.
  # Enabling this setting does not affect the previously stored bucket policy, except that public and cross-account access within the public bucket policy,
  # including non-public delegation to specific accounts, is blocked. When set to true:
  # Only the bucket owner and AWS Services can access this buckets if it has a public policy.
  restrict_public_buckets = true
}

############################################
#                  ROLES                   #
############################################

resource "aws_iam_role" "SftpWithPw-ApiRole" {
    name               = "SftpWithPw-ApiRole"
    path               = "/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "SftpWithPw-LambdaRole" {
    name               = "SftpWithPw-LambdaRole"
    path               = "/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "SftpWithPw-TransferLoggingRole" {
    name               = "SftpWithPw-TransferLoggingRole"
    path               = "/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "transfer.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "SftpWithPw-TransferInvocationRole" {
    name               = "SftpWithPw-TransferInvocationRole"
    path               = "/"
    assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "transfer.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

###########################################
#                POLICIES                 #
###########################################

resource "aws_iam_role_policy" "SftpWithPw-Api-LoggingPolicy" {
    name   = "SftpWithPw-Api-LoggingPolicy"
    role   = aws_iam_role.SftpWithPw-ApiRole.id
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ApiLoggingPolicy",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "SftpWithPw-Lambda-LoggingPolicy" {
    name   = "SftpWithPw-Lambda-LoggingPolicy"
    role   = aws_iam_role.SftpWithPw-LambdaRole.id
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaLoggingPolicy",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "SftpWithPw-Lambda-SecretsPolicy" {
    name   = "SftpWithPw-Lambda-SecretsPolicy"
    role   = aws_iam_role.SftpWithPw-LambdaRole.id

    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaGetSecretsPolicy",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:${var.sftp_parameter_prefix}*",
      "Effect": "Allow"
    }
  ]
}
POLICY
/*
    policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "LambdaGetParametersPolicy",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameters",
                "ssm:GetParameter",
                "ssm:GetParameterHistory"
            ],
            "Resource": "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter${var.sftp_parameter_prefix}*"
        }
    ]
}
POLICY
*/
}

resource "aws_iam_role_policy" "SftpWithPw-Transfer-ApiGetPolicy" {
    name   = "SftpWithPw-Transfer-ApiGetPolicy"
    role   = aws_iam_role.SftpWithPw-TransferInvocationRole.id
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TransferApiGetPolicy",
      "Action": [
        "apigateway:GET"
      ],
      "Resource": "*",
      "Effect": "Allow"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "SftpWithPw-Transfer-ApiInvokePolicy" {
    name   = "SftpWithPw-Transfer-ApiInvokePolicy"
    role   = aws_iam_role.SftpWithPw-TransferInvocationRole.id
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TransferApiInvokePolicy",
      "Action": [
        "execute-api:Invoke"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id}/prod/GET/*"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "SftpWithPw-Transfer-LoggingPolicy" {
    name   = "SftpWithPw-Transfer-LoggingPolicy"
    role   = aws_iam_role.SftpWithPw-TransferLoggingRole.id
    policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TransferLoggingPolicy",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:PutLogEvents"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "SftpWithPw-Transfer-S3FullAccessToSftpBucketPolicy" {
  name    = "SftpWithPw-Transfer-S3FullAccessToSftpBucketPolicy"
  role    = aws_iam_role.SftpWithPw-TransferInvocationRole.id
  policy  = <<POLICY
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid": "TransferS3FullAccessToSftpBucketPolicy",
      "Action":[
        "s3:ListBucket",
        "s3:GetBucketLocation"
      ],
      "Effect":"Allow",
      "Resource":"arn:aws:s3:::${local.sftp_bucket}"
    },
    {
      "Action":[
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectAcl",
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:DeleteObject"
      ],
      "Effect":"Allow",
      "Resource": [
        "arn:aws:s3:::${local.sftp_bucket}",
        "arn:aws:s3:::${local.sftp_bucket}/*"
      ]
    }
  ]
}
POLICY
}

###########################################
#                  LAMBDA                 #
###########################################

locals {
  source_files = ["sftp-auth-lambda.py", "t1"]
}

data "template_file" "t_file" {
  count = length(local.source_files)
  template = file(element(local.source_files, count.index))
}

resource "local_file" "to_temp_dir" {
  count    = length(local.source_files)
  filename = "${path.module}/temp/${basename(element(local.source_files, count.index))}"
  content  = element(data.template_file.t_file.*.rendered, count.index)
}

data "archive_file" "sftp-auth-lambda" {
  type        = "zip"
  source_dir  = "${path.module}/temp"
  output_path = "sftp-auth-lambda.zip"
  depends_on = [ local_file.to_temp_dir ]
}

#data "archive_file" "sftp-auth-lambda" {
#  type        = "zip"
#  source_file = "sftp-auth-lambda.py"
#  output_path = "sftp-auth-lambda.zip"
#}

resource "aws_lambda_function" "SftpWithPw-GetUserConfigLambdaFunction" {
  filename          = "sftp-auth-lambda.zip"
  function_name     = "SftpWithPw-GetUserConfigLambdaFunction"
  role              = aws_iam_role.SftpWithPw-LambdaRole.arn
  handler           = "sftp-auth-lambda.lambda_handler"
  runtime           = "python3.7"
  description       = "A function to lookup and return user data from AWS Secrets Manager."
  source_code_hash  = data.archive_file.sftp-auth-lambda.output_base64sha256
  environment {
    variables = {
      "SecretsManagerRegion" = var.region
    }
  }
}

resource "aws_lambda_permission" "SftpWithPw-GetUserConfigLambdaPermission" {
  statement_id  = "GetUserConfigLambdaPermission"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.SftpWithPw-GetUserConfigLambdaFunction.arn
  principal     = "apigateway.amazonaws.com"
  source_arn    = "arn:aws:execute-api:${var.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id}/*"
}

###########################################
#               API GATEWAY               #
###########################################

resource "aws_api_gateway_rest_api" "SftpWithPw-CustomIdentityProviderApi" {
  name        = "SftpWithPw-CustomIdentityProviderApi"
  description = "API used for GetUserConfig requests"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

resource "aws_api_gateway_model" "SftpWithPw-ApiGetUserConfigResponseModel" {
  rest_api_id  = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  name         = "ApiGetUserConfigResponseModel"
  description  = "API response for GetUserConfig"
  content_type = "application/json"
  schema = <<EOF
{
  "title": "UserConfig",
  "type": "object",
  "properties": {
    "HomeDirectory": { "type": string },
    "Role":          { "type": string },
    "Policy":        { "type": string },
    "PublicKeys":    { "type": string, "items": { "type": string } }
  }
}
EOF
}

resource "aws_api_gateway_account" "SftpWithPw-ApiLoggingAccount" {
  cloudwatch_role_arn = aws_iam_role.SftpWithPw-ApiRole.arn
}

resource "aws_api_gateway_method" "SftpWithPw-GetUserConfigRequest" {
  depends_on = [
    aws_api_gateway_model.SftpWithPw-ApiGetUserConfigResponseModel
  ]
  rest_api_id         = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  resource_id         = aws_api_gateway_resource.SftpWithPw-GetUserConfigResource.id
  http_method         = "GET"
  authorization       = "AWS_IAM"
  request_parameters  = {
    "method.request.header.Password" = false
  }
}

resource "null_resource" "method-delay" {
  provisioner "local-exec" {
    command = "sleep 5"
  }
  triggers = {
    response = aws_api_gateway_resource.SftpWithPw-GetUserConfigResource.id
  }
}

resource "aws_api_gateway_method_response" "SftpWithPw-ApiResponseOk" {
  depends_on = [
    null_resource.method-delay,
    aws_api_gateway_model.SftpWithPw-ApiGetUserConfigResponseModel,
    aws_api_gateway_resource.SftpWithPw-GetUserConfigResource
  ]
  rest_api_id     = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  resource_id     = aws_api_gateway_resource.SftpWithPw-GetUserConfigResource.id
  http_method     = "GET"
  status_code     = "200"
  response_models = {
    "application/json" = aws_api_gateway_model.SftpWithPw-ApiGetUserConfigResponseModel.name
  }
}

resource "aws_api_gateway_integration" "SftpWithPw-ApiIntegration" {
  rest_api_id             = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  resource_id             = aws_api_gateway_resource.SftpWithPw-GetUserConfigResource.id
  http_method             = aws_api_gateway_method.SftpWithPw-GetUserConfigRequest.http_method
  type                    = "AWS"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.SftpWithPw-GetUserConfigLambdaFunction.invoke_arn
  request_templates       = {
    "application/json"    = <<EOF
{
  "username": "$input.params('username')",
  "password": "$util.escapeJavaScript($input.params('Password')).replaceAll("\\'","'")",
  "serverId": "$input.params('serverId')"
}
EOF
  }
}

resource "aws_api_gateway_integration_response" "SftpWithPw-ApiIntegrationResponse" {
  depends_on = [
    aws_api_gateway_integration.SftpWithPw-ApiIntegration,
    aws_api_gateway_method_response.SftpWithPw-ApiResponseOk
  ]
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  resource_id = aws_api_gateway_resource.SftpWithPw-GetUserConfigResource.id
  http_method = aws_api_gateway_method.SftpWithPw-GetUserConfigRequest.http_method
  status_code = "200"
}

resource "aws_api_gateway_deployment" "SftpWithPw-ApiDeployment" {
  depends_on = [ # required as per documentation!
    aws_api_gateway_integration.SftpWithPw-ApiIntegration
  ]
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
}

resource "aws_api_gateway_stage" "SftpWithPw-ApiStage" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  deployment_id = aws_api_gateway_deployment.SftpWithPw-ApiDeployment.id
}

resource "aws_api_gateway_method_settings" "SftpWithPw-ApiStageMethodSettings" {
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  stage_name  = aws_api_gateway_stage.SftpWithPw-ApiStage.stage_name
  method_path = "*/*"
  settings {
    metrics_enabled     = true
    logging_level       = "INFO"
    data_trace_enabled  = false # = "Log full request/response data": must be set to "false"; otherwise it would reveal passwords in Cloudwatch logs!
  }
}

resource "aws_api_gateway_resource" "SftpWithPw-ApiServersResource" {
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  parent_id   = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.root_resource_id
  path_part   = "servers"
}

resource "aws_api_gateway_resource" "SftpWithPw-ApiServerIdResource" {
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  parent_id   = aws_api_gateway_resource.SftpWithPw-ApiServersResource.id
  path_part   = "{serverId}"
}

resource "aws_api_gateway_resource" "SftpWithPw-ApiUsersResource" {
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  parent_id   = aws_api_gateway_resource.SftpWithPw-ApiServerIdResource.id
  path_part   = "users"
}

resource "aws_api_gateway_resource" "SftpWithPw-ApiUserNameResource" {
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  parent_id   = aws_api_gateway_resource.SftpWithPw-ApiUsersResource.id
  path_part   = "{username}"
}

resource "aws_api_gateway_resource" "SftpWithPw-GetUserConfigResource" {
  rest_api_id = aws_api_gateway_rest_api.SftpWithPw-CustomIdentityProviderApi.id
  parent_id   = aws_api_gateway_resource.SftpWithPw-ApiUserNameResource.id
  path_part   = "config"
}

###########################################
#            SFTP SERVER                  #
###########################################

resource "aws_transfer_server" "SftpWithPw-TransferServer" {
  identity_provider_type = "API_GATEWAY"
  invocation_role        = aws_iam_role.SftpWithPw-TransferInvocationRole.arn
  logging_role           = aws_iam_role.SftpWithPw-TransferLoggingRole.arn
  endpoint_type          = "PUBLIC"
  url                    = aws_api_gateway_stage.SftpWithPw-ApiStage.invoke_url
}

# resource "aws_route53_record" "sftp_cname_entry" {
#   ttl = 60
#   zone_id = data.terraform_remote_state.tf_network.outputs.route53_servicezone_id
#   name = "sftp.service.${data.terraform_remote_state.tf_shared.outputs.domain_name}"
#   type = "CNAME"
#   records = [ aws_transfer_server.sftp.endpoint ]
# }


###########################################
#                 OUTPUT                  #
###########################################

output "sftp_bucket" {
  value = local.sftp_bucket
}

output "invoke_url_api_gateway_stage" {
  value = aws_api_gateway_stage.SftpWithPw-ApiStage.invoke_url
}

output "sftp_server_endpoint_url" {
  value = aws_transfer_server.SftpWithPw-TransferServer.endpoint
}
