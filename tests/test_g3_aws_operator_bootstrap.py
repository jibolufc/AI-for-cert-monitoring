from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_PATH = ROOT / "infra/aws/g3-synthetic/operator-bootstrap.json"


class G3AwsOperatorBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads(BOOTSTRAP_PATH.read_text(encoding="utf-8"))
        self.resources = self.template["Resources"]

    def _statements(self, resource_name: str):
        resource = self.resources[resource_name]
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            return resource["Properties"]["PolicyDocument"]["Statement"]
        return resource["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]

    def test_operator_is_not_granted_direct_provisioning_or_admin(self):
        statements = self._statements("OperatorDeploymentPolicy")
        actions = {
            action
            for statement in statements
            for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
        }
        self.assertNotIn("iam:CreateRole", actions)
        self.assertNotIn("lambda:CreateFunction", actions)
        self.assertNotIn("ec2:CreateSecurityGroup", actions)
        self.assertNotIn("cloudformation:*", actions)
        self.assertNotIn("iam:*", actions)

    def test_operator_can_pass_only_the_dedicated_cloudformation_role(self):
        statements = self._statements("OperatorDeploymentPolicy")
        pass_role = next(item for item in statements if item["Sid"] == "PassOnlyApprovedCloudFormationRole")
        self.assertEqual(pass_role["Resource"], {"Fn::GetAtt": ["CloudFormationExecutionRole", "Arn"]})
        self.assertEqual(
            pass_role["Condition"]["StringEquals"]["iam:PassedToService"],
            "cloudformation.amazonaws.com",
        )
        self.assertEqual(pass_role["Condition"]["Bool"]["aws:MultiFactorAuthPresent"], "true")

    def test_change_set_creation_requires_the_approved_role_and_mfa(self):
        statements = self._statements("OperatorDeploymentPolicy")
        create = next(item for item in statements if item["Sid"] == "CreateReviewedChangeSetUsingOnlyApprovedRole")
        self.assertEqual(
            create["Condition"]["StringEquals"]["cloudformation:RoleArn"],
            {"Fn::GetAtt": ["CloudFormationExecutionRole", "Arn"]},
        )
        self.assertEqual(create["Condition"]["Bool"]["aws:MultiFactorAuthPresent"], "true")

    def test_non_mfa_sessions_are_denied_except_mfa_enrolment(self):
        statements = self._statements("OperatorSelfMfaPolicy")
        deny = next(item for item in statements if item["Sid"] == "DenyAllOtherActionsWithoutMfa")
        self.assertEqual(deny["Effect"], "Deny")
        self.assertEqual(deny["Condition"]["BoolIfExists"]["aws:MultiFactorAuthPresent"], "false")
        self.assertIn("iam:EnableMFADevice", deny["NotAction"])
        self.assertNotIn("cloudformation:ExecuteChangeSet", deny["NotAction"])

    def test_service_role_is_bounded_and_cannot_create_endpoints_or_users(self):
        statements = self._statements("CloudFormationExecutionRole")
        actions = {
            action
            for statement in statements
            for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
        }
        self.assertNotIn("ec2:CreateVpcEndpoint", actions)
        self.assertNotIn("iam:CreateUser", actions)
        self.assertNotIn("iam:AttachRolePolicy", actions)
        self.assertNotIn("s3:DeleteObject", actions)
        self.assertNotIn("s3:DeleteBucket", actions)
        self.assertFalse(any(action.startswith("secretsmanager:") for action in actions))

    def test_secretless_scope_grants_no_secrets_manager_permission(self):
        for resource_name in (
            "WorkloadPermissionsBoundary",
            "CloudFormationExecutionRole",
            "OperatorDeploymentPolicy",
        ):
            statements = self._statements(resource_name)
            actions = {
                action
                for statement in statements
                for action in (
                    [statement["Action"]]
                    if isinstance(statement["Action"], str)
                    else statement["Action"]
                )
            }
            self.assertFalse(
                any(action.startswith("secretsmanager:") for action in actions),
                resource_name,
            )

    def test_workload_role_creation_requires_the_boundary(self):
        statements = self._statements("CloudFormationExecutionRole")
        create_role = next(item for item in statements if item["Sid"] == "CreateBoundedSyntheticWorkloadRole")
        self.assertEqual(
            create_role["Condition"]["StringEquals"]["iam:PermissionsBoundary"],
            {"Ref": "WorkloadPermissionsBoundary"},
        )

    def test_log_group_discovery_is_read_only_and_separate_from_exact_writes(self):
        statements = self._statements("CloudFormationExecutionRole")
        discovery = next(
            item for item in statements
            if item["Sid"] == "DescribeLogGroupsForArnResolution"
        )
        self.assertEqual(discovery["Action"], "logs:DescribeLogGroups")
        self.assertEqual(discovery["Resource"], "*")

        management = next(
            item for item in statements
            if item["Sid"] == "ManageExactSyntheticLogGroup"
        )
        self.assertNotIn("logs:DescribeLogGroups", management["Action"])
        self.assertEqual(
            management["Resource"],
            {
                "Fn::Sub": (
                    "arn:${AWS::Partition}:logs:${TargetRegion}:${AWS::AccountId}:"
                    "log-group:/aws/lambda/ccp-g3-${TargetStackName}:*"
                )
            },
        )

    def test_staging_bucket_is_private_encrypted_and_short_lived(self):
        bucket = self.resources["TemplateStagingBucket"]["Properties"]
        self.assertTrue(all(bucket["PublicAccessBlockConfiguration"].values()))
        self.assertEqual(bucket["LifecycleConfiguration"]["Rules"][0]["ExpirationInDays"], 7)
        self.assertEqual(
            bucket["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]
            ["ServerSideEncryptionByDefault"]["SSEAlgorithm"],
            "AES256",
        )

    def test_operator_can_list_only_the_template_staging_bucket(self):
        statements = self._statements("OperatorDeploymentPolicy")
        listing = next(item for item in statements if item["Sid"] == "ViewTemplateStagingBucket")
        self.assertEqual(listing["Action"], ["s3:GetBucketLocation", "s3:ListBucket"])
        self.assertEqual(listing["Resource"], {"Fn::GetAtt": ["TemplateStagingBucket", "Arn"]})
        self.assertEqual(listing["Condition"], {"Bool": {"aws:MultiFactorAuthPresent": "true"}})

    def test_operator_network_visibility_is_read_only_and_mfa_gated(self):
        statements = self._statements("OperatorDeploymentPolicy")
        lookup = next(
            item for item in statements
            if item["Sid"] == "ReadVerifiedNetworkChoicesForCloudFormation"
        )
        self.assertEqual(
            lookup["Action"],
            [
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeVpcs",
            ],
        )
        self.assertEqual(lookup["Resource"], "*")
        self.assertEqual(lookup["Condition"], {"Bool": {"aws:MultiFactorAuthPresent": "true"}})

    def test_operator_can_read_only_the_exact_workload_role(self):
        statements = self._statements("OperatorDeploymentPolicy")
        role = next(item for item in statements if item["Sid"] == "ReadExactSyntheticWorkloadRole")
        self.assertEqual(
            role["Action"],
            ["iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"],
        )
        self.assertEqual(
            role["Resource"],
            {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/${TargetStackName}-SyntheticWorkloadRole-*"},
        )
        self.assertEqual(role["Condition"], {"Bool": {"aws:MultiFactorAuthPresent": "true"}})

    def test_operator_can_invoke_only_the_exact_synthetic_runner_with_mfa(self):
        statements = self._statements("OperatorDeploymentPolicy")
        runner = next(item for item in statements if item["Sid"] == "ReadAndInvokeExactSyntheticRunner")
        self.assertIn("lambda:InvokeFunction", runner["Action"])
        self.assertEqual(
            runner["Resource"],
            {
                "Fn::Sub": (
                    "arn:${AWS::Partition}:lambda:${TargetRegion}:${AWS::AccountId}:"
                    "function:ccp-g3-${TargetStackName}"
                )
            },
        )
        self.assertEqual(runner["Condition"], {"Bool": {"aws:MultiFactorAuthPresent": "true"}})

    def test_operator_evidence_reads_are_prefix_bounded_and_mfa_gated(self):
        statements = self._statements("OperatorDeploymentPolicy")
        objects = next(item for item in statements if item["Sid"] == "ReadSyntheticEvidenceObjectsOnly")
        listing = next(item for item in statements if item["Sid"] == "ListSyntheticEvidencePrefixOnly")
        logs = next(item for item in statements if item["Sid"] == "ReadExactSyntheticLogGroup")

        self.assertEqual(objects["Action"], "s3:GetObject")
        self.assertEqual(
            objects["Resource"],
            {"Fn::Sub": "arn:${AWS::Partition}:s3:::${TargetStackName}-*/runs/*"},
        )
        self.assertEqual(listing["Action"], "s3:ListBucket")
        self.assertEqual(listing["Condition"]["StringLike"]["s3:prefix"], ["runs", "runs/*"])
        self.assertEqual(
            logs["Resource"],
            {
                "Fn::Sub": (
                    "arn:${AWS::Partition}:logs:${TargetRegion}:${AWS::AccountId}:"
                    "log-group:/aws/lambda/ccp-g3-${TargetStackName}:*"
                )
            },
        )
        for statement in (objects, listing, logs):
            self.assertEqual(statement["Condition"]["Bool"]["aws:MultiFactorAuthPresent"], "true")

    def test_operator_can_read_but_not_mutate_evidence_bucket_configuration(self):
        statements = self._statements("OperatorDeploymentPolicy")
        config = next(
            item for item in statements
            if item["Sid"] == "ReadSyntheticEvidenceBucketConfiguration"
        )
        self.assertEqual(
            config["Action"],
            [
                "s3:GetBucketLocation",
                "s3:GetBucketPolicy",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketVersioning",
                "s3:GetEncryptionConfiguration",
                "s3:GetLifecycleConfiguration",
            ],
        )
        self.assertTrue(all(action.startswith("s3:Get") for action in config["Action"]))
        self.assertEqual(
            config["Resource"],
            {"Fn::Sub": "arn:${AWS::Partition}:s3:::${TargetStackName}-*"},
        )
        self.assertEqual(config["Condition"], {"Bool": {"aws:MultiFactorAuthPresent": "true"}})

if __name__ == "__main__":
    unittest.main()
