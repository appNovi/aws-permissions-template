provider "aws" {
  region = "us-west-2"
}

resource "aws_iam_user" "user" {
  name = "iam_user_name"
  path = "/"
}

data "aws_iam_policy_document" "policy" {
    statement {
        sid = "VisualEditor0"
        effect = "Allow"

        actions = [
            "acm:DescribeCertificate",
				"acm:ListCertificates",
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribePolicies",
                "autoscaling:DescribeAutoScalingInstances",
				"apigateway:GET",
				"appstream:DescribeFleets",
				"appstream:DescribeStacks",
				"appstream:DescribeUserStackAssociations",
				"appstream:DescribeUsers",
				"appstream:ListAssociatedFleets",
                "backup:ListBackupPlans",
                "backup:ListBackupVaults",
				"cloudfront:GetDistribution",
				"cloudfront:ListDistributions",
				"dynamodb:DescribeGlobalTable",
				"dynamodb:DescribeGlobalTableSettings",
				"dynamodb:DescribeTable",
				"dynamodb:ListGlobalTables",
				"dynamodb:ListTables",
				"ec2:DescribeAddresses",
				"ec2:DescribeFlowLogs",
				"ec2:DescribeImages",
				"ec2:DescribeInstances",
				"ec2:DescribeInternetGateways",
				"ec2:DescribeNatGateways",
				"ec2:DescribeRouteTables",
				"ec2:DescribeSecurityGroups",
				"ec2:DescribeSnapshotAttribute",
				"ec2:DescribeSnapshots",
				"ec2:DescribeSubnets",
				"ec2:DescribeTags",
                "ec2:DescribeRegions",
				"ec2:DescribeVolumes",
				"ec2:DescribeVpcPeeringConnections",
				"ec2:DescribeVpcs",
				"ecr-public:DescribeImages",
				"ecr-public:DescribeRegistries",
				"ecr-public:DescribeRepositories",
				"ecr:DescribeImages",
				"ecr:DescribeRegistry",
				"ecr:DescribeRepositories",
				"ecs:DescribeClusters",
				"ecs:DescribeContainerInstances",
				"ecs:DescribeServices",
				"ecs:DescribeTasks",
				"ecs:ListClusters",
				"ecs:ListContainerInstances",
				"ecs:ListServices",
				"ecs:ListTagsForResource",
				"ecs:ListTasks",
				"eks:DescribeCluster",
				"eks:ListClusters",
				"elasticloadbalancing:DescribeListeners",
				"elasticloadbalancing:DescribeLoadBalancerPolicies",
				"elasticloadbalancing:DescribeLoadBalancers",
				"elasticloadbalancing:DescribeSSLPolicies",
				"elasticloadbalancing:DescribeTargetGroups",
				"elasticloadbalancing:DescribeTargetHealth",
				"es:DescribeElasticsearchDomain",
				"es:ListDomainNames",
				"fsx:DescribeFileSystems",
				"guardduty:GetDetector",
				"guardduty:GetFilter",
				"guardduty:GetFindings",
				"guardduty:GetMembers",
				"guardduty:ListDetectors",
				"guardduty:ListFilters",
				"guardduty:ListFindings",
				"guardduty:ListMembers",
				"iam:GenerateCredentialReport",
				"iam:GenerateServiceLastAccessedDetails",
				"iam:GetAccessKeyLastUsed",
				"iam:GetAccountPasswordPolicy",
				"iam:GetAccountSummary",
				"iam:GetCredentialReport",
				"iam:GetLoginProfile",
				"iam:GetPolicy",
				"iam:GetPolicyVersion",
				"iam:GetRole",
				"iam:GetRolePolicy",
				"iam:GetServiceLastAccessedDetails",
				"iam:GetUser",
				"iam:GetUserPolicy",
				"iam:ListAccessKeys",
				"iam:ListAccountAliases",
				"iam:ListAttachedGroupPolicies",
				"iam:ListAttachedRolePolicies",
				"iam:ListAttachedUserPolicies",
				"iam:ListEntitiesForPolicy",
				"iam:ListGroups",
				"iam:ListGroupsForUser",
				"iam:ListInstanceProfilesForRole",
				"iam:ListMFADevices",
				"iam:ListPolicies",
				"iam:ListRolePolicies",
				"iam:ListRoles",
				"iam:ListUserPolicies",
				"iam:ListUserTags",
				"iam:ListUsers",
				"iam:ListVirtualMFADevices",
				"inspector2:ListFindings",
                "inspector2:ListMembers",
                "inspector:ListMembers",
				"inspector:DescribeFindings",
				"inspector:ListFindings",
				"lambda:GetFunctionUrlConfig",
				"lambda:GetPolicy",
				"lambda:ListFunctions",
				"lambda:ListTags",
				"macie2:GetFindings",
				"macie2:ListFindings",
				"macie2:ListMembers",
				"organizations:DescribeAccount",
				"organizations:DescribeEffectivePolicy",
				"organizations:DescribeOrganization",
				"organizations:DescribePolicy",
				"organizations:ListAccounts",
				"organizations:ListPoliciesForTarget",
				"organizations:ListTagsForResource",
				"rds:DescribeDBClusters",
				"rds:DescribeDBInstances",
				"rds:DescribeOptionGroups",
				"route53:ListHostedZones",
				"route53:ListResourceRecordSets",
				"s3:GetAccountPublicAccessBlock",
				"s3:GetBucketAcl",
				"s3:GetBucketLocation",
				"s3:GetBucketLogging",
				"s3:GetBucketPolicy",
				"s3:GetBucketPolicyStatus",
				"s3:GetBucketPublicAccessBlock",
				"s3:GetBucketTagging",
				"s3:GetEncryptionConfiguration",
				"s3:ListAllMyBuckets",
				"s3:ListBucket",
				"secretsmanager:GetResourcePolicy",
				"secretsmanager:ListSecrets",
				"securityhub:DescribeHub",
				"securityhub:GetFindings",
				"securityhub:ListMembers",
				"securityhub:ListTagsForResource",
				"sns:ListSubscriptionsByTopic",
				"ssm:DescribeAvailablePatches",
				"ssm:DescribeInstanceInformation",
				"ssm:DescribeInstancePatches",
				"ssm:DescribePatchGroups",
				"ssm:GetInventorySchema",
				"ssm:ListInventoryEntries",
				"ssm:ListResourceComplianceSummaries",
				"ssm:ListTagsForResource",
				"waf-regional:GetWebACL",
				"waf-regional:GetWebACLForResource",
				"waf-regional:ListWebACLs",
				"waf:GetWebACL",
				"waf:ListWebACLs",
				"wafv2:GetWebACL",
				"wafv2:GetWebACLForResource",
				"wafv2:ListWebACLs",
				"workspaces:DescribeTags",
				"workspaces:DescribeWorkspaceDirectories",
				"workspaces:DescribeWorkspaces",
				"workspaces:DescribeWorkspacesConnectionStatus"
        ]

        resources = ["*"]
    }
}

resource "aws_iam_policy" "policy" {
  name        = "appNovi_policy"
  description = "An appNovi asset management policy"
  policy      = data.aws_iam_policy_document.policy.json
}

resource "aws_iam_policy_attachment" "attach" {
  name       = "aN_attachment"
  users      = [aws_iam_user.user.name]
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_access_key" "user_key" {
  user = aws_iam_user.user.name
}

output "access_key_id" {
  value = aws_iam_access_key.user_key.id
}

output "secret_access_key" {
  value = aws_iam_access_key.user_key.secret
  sensitive = true
}

resource "local_file" "credentials" {
  sensitive_content = "Access Key ID: ${aws_iam_access_key.user_key.id}\nSecret Access Key: ${aws_iam_access_key.user_key.secret}"
  filename          = "${path.module}/credentials.txt"
}