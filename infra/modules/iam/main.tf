###################################
# helm main.tf
###################################

data "aws_caller_identity" "current" {}

###################################
# 2. Load Balancer Controller Resources
###################################

# IAM Policy for ALB Controller
data "aws_iam_policy" "lb_controller_policy" {
  name = "AWSLoadBalancerControllerIAMPolicy"
}

# IAM Role for ALB Controller (IRSA)
resource "aws_iam_role" "lb_controller_role" {
  name = "eks-lb-controller-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = var.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${replace(var.oidc_provider_url, "https://", "")}:sub" = "system:serviceaccount:kube-system:alb-controller"
            "${replace(var.oidc_provider_url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Attach existing AWS policy to role
resource "aws_iam_role_policy_attachment" "lb_controller_attach" {
  role       = aws_iam_role.lb_controller_role.name
  policy_arn = data.aws_iam_policy.lb_controller_policy.arn
}

###################################
# 3. External DNS Resources
###################################

# Custom IAM Policy for Route53 access
resource "aws_iam_policy" "external_dns_policy" {
  name        = "ExternalDNSIAMPolicy"
  description = "IAM policy for External DNS to manage Route53 records"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets",
          "route53:ListHostedZones",
          "route53:ListTagsForResource"
        ],
        Resource = "*"
      }
    ]
  })
}

# IAM Role for External DNS (IRSA)
resource "aws_iam_role" "external_dns_role" {
  name = "eks-external-dns-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRoleWithWebIdentity"
        Effect = "Allow"
        Principal = {
          Federated = var.oidc_provider_arn
        }
        Condition = {
          StringEquals = {
            "${replace(var.oidc_provider_url, "https://", "")}:sub" = "system:serviceaccount:kube-system:external-dns"
          }
        }
      }
    ]
  })
}

# Attach policies for Route53 management
resource "aws_iam_role_policy_attachment" "external_dns_attach_custom" {
  role       = aws_iam_role.external_dns_role.name
  policy_arn = aws_iam_policy.external_dns_policy.arn
}

