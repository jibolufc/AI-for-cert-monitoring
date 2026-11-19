from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / "infra/aws/g3-synthetic/template.json"


class G3AwsTemplateTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
        self.resources = self.template["Resources"]

    def test_template_uses_existing_verified_network(self):
        self.assertEqual(self.template["Parameters"]["ExistingVpcId"]["Type"], "AWS::EC2::VPC::Id")
        function = self.resources["SyntheticEvidenceFunction"]["Properties"]
        self.assertEqual(function["VpcConfig"]["SubnetIds"], {"Ref": "PrivateSubnetIds"})
        endpoint = self.resources["S3GatewayEndpoint"]["Properties"]
        self.assertEqual(endpoint["RouteTableIds"], {"Ref": "PrivateRouteTableIds"})
        self.assertEqual(endpoint["VpcEndpointType"], "Gateway")
        self.assertEqual(self.template["Parameters"]["PrivateRouteTableIds"]["Type"], "CommaDelimitedList")
        self.assertEqual(self.resources["S3GatewayEndpoint"]["Condition"], "ShouldCreateS3GatewayEndpoint")
        self.assertEqual(self.template["Parameters"]["CreateS3GatewayEndpoint"]["Default"], "false")

    def test_template_creates_no_public_or_continuously_running_workload(self):
        prohibited = {
            "AWS::EC2::Instance",
            "AWS::EC2::NatGateway",
            "AWS::EC2::InternetGateway",
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "AWS::ECS::Service",
            "AWS::RDS::DBInstance",
        }
        resource_types = {resource["Type"] for resource in self.resources.values()}
        self.assertFalse(resource_types & prohibited)
        self.assertEqual(
            self.resources["S3GatewayEndpoint"]["Properties"]["VpcEndpointType"],
            "Gateway",
        )

    def test_security_group_has_no_ingress_and_s3_only_https_egress(self):
        properties = self.resources["SyntheticWorkloadSecurityGroup"]["Properties"]
        self.assertNotIn("SecurityGroupIngress", properties)
        self.assertEqual(
            properties["SecurityGroupEgress"],
            [{
                "Description": "HTTPS to the regional S3 prefix list only",
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "DestinationPrefixListId": {"Ref": "S3PrefixListId"},
            }],
        )

    def test_no_rule_reaches_any_ip_range(self):
        # A NAT gateway on the private route tables must not turn into internet
        # egress: no IPv4 or IPv6 CIDR destination is allowed in any rule.
        for rule in self.resources["SyntheticWorkloadSecurityGroup"]["Properties"]["SecurityGroupEgress"]:
            self.assertNotIn("CidrIp", rule)
            self.assertNotIn("CidrIpv6", rule)
        self.assertNotIn("0.0.0.0/0", json.dumps(self.template))
        self.assertNotIn("::/0", json.dumps(self.template))

    def test_s3_prefix_list_parameter_is_required_and_constrained(self):
        parameter = self.template["Parameters"]["S3PrefixListId"]
        self.assertEqual(parameter["Type"], "String")
        self.assertNotIn("Default", parameter)
        self.assertEqual(parameter["AllowedPattern"], "^pl-[0-9a-f]{8,17}$")
        example = json.loads(
            (ROOT / "infra" / "aws" / "g3-synthetic" / "parameters.example.json").read_text()
        )
        self.assertIn("S3PrefixListId", {item["ParameterKey"] for item in example})

    def test_evidence_bucket_is_private_encrypted_versioned_and_bounded(self):
        bucket = self.resources["SyntheticEvidenceBucket"]["Properties"]
        self.assertEqual(bucket["VersioningConfiguration"]["Status"], "Enabled")
        self.assertEqual(
            bucket["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
            ["ServerSideEncryptionByDefault"]["SSEAlgorithm"],
            "AES256",
        )
        self.assertTrue(all(bucket["PublicAccessBlockConfiguration"].values()))
        self.assertEqual(bucket["LifecycleConfiguration"]["Rules"][0]["ExpirationInDays"], 30)
        policy = self.resources["SyntheticEvidenceBucketPolicy"]["Properties"]["PolicyDocument"]
        self.assertEqual(policy["Statement"][0]["Condition"], {"Bool": {"aws:SecureTransport": "false"}})
        self.assertEqual(self.resources["SyntheticEvidenceBucketPolicy"]["DeletionPolicy"], "Retain")
        self.assertEqual(self.resources["SyntheticEvidenceBucketPolicy"]["UpdateReplacePolicy"], "Retain")

    def test_workload_identity_is_bounded_and_has_no_lifecycle_authority(self):
        self.assertEqual(
            self.resources["SyntheticWorkloadRole"]["Properties"]["PermissionsBoundary"],
            {"Ref": "WorkloadPermissionsBoundaryArn"},
        )
        statements = self.resources["SyntheticWorkloadRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        actions = {
            action
            for statement in statements
            for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
        }
        self.assertFalse(actions & {"kms:*", "secretsmanager:*", "iam:*", "acm:*", "acm-pca:*"})
        self.assertFalse(any(action.startswith("secretsmanager:") for action in actions))
        self.assertFalse(actions & {"s3:DeleteObject", "ec2:RunInstances", "lambda:InvokeFunction"})
        self.assertIn("s3:PutObject", actions)
        self.assertIn("s3:GetObject", actions)
        log_statement = next(item for item in statements if item["Sid"] == "WriteBoundedLogs")
        self.assertEqual(log_statement["Resource"], {"Fn::GetAtt": ["SyntheticLogGroup", "Arn"]})

    def test_function_uses_role_credentials_not_embedded_credentials(self):
        function = self.resources["SyntheticEvidenceFunction"]["Properties"]
        self.assertEqual(function["Role"], {"Fn::GetAtt": ["SyntheticWorkloadRole", "Arn"]})
        self.assertEqual(
            set(function["Environment"]["Variables"]),
            {"EVIDENCE_BUCKET", "EVIDENCE_LEVEL", "REAL_DATA_ENABLED"},
        )
        source = "\n".join(function["Code"]["ZipFile"]["Fn::Join"][1])
        for forbidden in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "aws_access_key_id", "aws_secret_access_key"):
            self.assertNotIn(forbidden, source)

    def test_central_log_group_is_explicit_and_retained_for_thirty_days(self):
        log_group = self.resources["SyntheticLogGroup"]
        self.assertEqual(log_group["Properties"]["RetentionInDays"], 30)
        function = self.resources["SyntheticEvidenceFunction"]
        self.assertIn("SyntheticLogGroup", function["DependsOn"])

    def test_function_fails_closed_on_real_data_and_unknown_actions(self):
        code = self.resources["SyntheticEvidenceFunction"]["Properties"]["Code"]["ZipFile"]["Fn::Join"][1]
        source = "\n".join(code)
        self.assertIn("real_data_enabled must be false", source)
        self.assertIn("data_classification must be synthetic", source)
        self.assertIn("only write and restore actions are permitted", source)
        self.assertEqual(
            self.resources["SyntheticEvidenceFunction"]["Properties"]["ReservedConcurrentExecutions"],
            {"Fn::If": ["ShouldEnableSyntheticInvocation", 1, 0]},
        )

    def test_synthetic_invocation_is_disabled_by_default_and_time_bounded(self):
        parameter = self.template["Parameters"]["SyntheticInvocationEnabled"]
        self.assertEqual(parameter["Default"], "false")
        self.assertEqual(parameter["AllowedValues"], ["true", "false"])
        self.assertEqual(
            self.template["Conditions"]["ShouldEnableSyntheticInvocation"],
            {"Fn::Equals": [{"Ref": "SyntheticInvocationEnabled"}, "true"]},
        )
        self.assertEqual(
            self.template["Outputs"]["SyntheticInvocationState"]["Value"],
            {"Fn::If": ["ShouldEnableSyntheticInvocation", "enabled-one-concurrent-invocation", "disabled"]},
        )

    def test_every_taggable_resource_is_marked_synthetic(self):
        taggable = (
            "SyntheticEvidenceBucket",
            "SyntheticLogGroup",
            "SyntheticWorkloadSecurityGroup",
            "SyntheticWorkloadRole",
            "S3GatewayEndpoint",
            "SyntheticEvidenceFunction",
        )
        for name in taggable:
            tags = {
                item["Key"]: item["Value"]
                for item in self.resources[name]["Properties"]["Tags"]
            }
            self.assertEqual(tags["Environment"], "g3-synthetic", name)
            self.assertEqual(tags["Project"], "Cryptographic-Control-Plane", name)


if __name__ == "__main__":
    unittest.main()
