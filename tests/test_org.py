# Copyright The Cloud Custodian Authors.
# SPDX-License-Identifier: Apache-2.0

import json
from unittest import mock

import boto3
import moto
import pytest

from botocore.exceptions import ClientError

from c7n.executor import MainThreadExecutor
from c7n.resources import org as org_module


template_body = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Queue": {"Type": "AWS::SQS::Queue"}},
    }
)


@pytest.fixture(scope="function")
def org_tree(request):
    with moto.mock_organizations():
        client = boto3.client("organizations")
        org = client.create_organization(FeatureSet="ALL")["Organization"]
        root = client.list_roots()["Roots"][0]

        dept_a = client.create_organizational_unit(ParentId=org["Id"], Name="DeptA")[
            "OrganizationalUnit"
        ]
        dept_b = client.create_organizational_unit(ParentId=org["Id"], Name="DeptB")[
            "OrganizationalUnit"
        ]
        group_c = client.create_organizational_unit(ParentId=dept_a["Id"], Name="GroupC")[
            "OrganizationalUnit"
        ]

        account_a = client.create_account(
            Email="a@example.com",
            AccountName="a",
            Tags=[{"Key": "Owner", "Value": "alice"}],
        )["CreateAccountStatus"]

        client.move_account(
            AccountId=account_a["AccountId"],
            SourceParentId=root["Id"],
            DestinationParentId=dept_a["Id"],
        )

        account_b = client.create_account(
            Email="b@example.com",
            AccountName="b",
            Tags=[{"Key": "Owner", "Value": "bob"}],
        )["CreateAccountStatus"]

        client.move_account(
            AccountId=account_b["AccountId"],
            SourceParentId=root["Id"],
            DestinationParentId=dept_b["Id"],
        )

        account_c = client.create_account(
            Email="c@example.com",
            AccountName="c",
            Tags=[{"Key": "Owner", "Value": "eve"}],
        )["CreateAccountStatus"]

        client.move_account(
            AccountId=account_c["AccountId"],
            SourceParentId=root["Id"],
            DestinationParentId=group_c["Id"],
        )
        with moto.mock_resourcegroupstaggingapi():
            yield dict(
                org=org,
                dept_a=dept_a,
                dept_b=dept_b,
                group_c=group_c,
                account_a=account_a,
                account_b=account_b,
                account_c=account_c,
                root=root,
            )


def test_org_account_ou_filter(test, org_tree):
    p = test.load_policy(
        {
            "name": "accounts",
            "resource": "aws.org-account",
            "filters": [{"type": "ou", "units": [org_tree["dept_a"]["Id"]]}],
        }
    )
    resources = p.run()
    assert {r["Id"] for r in resources} == {
        org_tree["account_a"]["AccountId"],
        org_tree["account_c"]["AccountId"],
    }

def test_org_describe(test):

    factory = test.replay_flight_data('test_org_account_describe')
    p = test.load_policy(
        {"name": "accounts",
         "resource": "aws.org-account",
         "filters": []},
        session_factory=factory
    )
    resources = p.run()
    assert len(resources) == 1
    assert resources[0]['Tags'] == [{'Key': 'i-am', 'Value': 'TheOriginalTim'}]

def test_org_account_moto(test, org_tree):
    p = test.load_policy(
        {
            "name": "accounts",
            "resource": "aws.org-account",
        },
    )
    resources = p.run()
    assert len(resources) == 4
    p = test.load_policy(
        {
            "name": "accounts",
            "resource": "aws.org-account",
            "filters": [{"Email": "c@example.com"}],
        },
    )
    resources = p.run()
    assert len(resources) == 1


@moto.mock_cloudformation
def test_org_account_filter_cfn_absent(test):
    p = test.load_policy(
        {
            "name": "org-cfn-check",
            "resource": "aws.org-account",
            "filters": [{"type": "cfn-stack", "stack_names": ["bob"]}],
        }
    )
    cfn_stack = p.resource_manager.filters[0]
    result = cfn_stack.process_account_region(
        {"Id": "123", "Name": "test-account"}, "us-east-1", boto3.Session()
    )
    assert result is True


@mock.patch("c7n.resources.org.account_session")
def test_org_account_filter_cfn_process(account_session, test):
    p = test.load_policy(
        {
            "name": "org-cfn-check",
            "resource": "aws.org-account",
            "filters": [
                {
                    "type": "cfn-stack",
                    "status": ["CREATE_COMPLETE", "UPDATE_COMPLETE"],
                    "stack_names": ["bob"],
                }
            ],
        }
    )
    cfn_stack = p.resource_manager.filters[0]
    cfn_stack.process_account_region = lambda *k: True
    result = cfn_stack.process([{"Id": "123", "Name": "test-account"}])
    assert result == [{'Id': '123', 'Name': 'test-account', 'c7n:cfn-stack': {'us-east-1': True}}]


@moto.mock_cloudformation
def test_org_account_filter_cfn_present(test):
    p = test.load_policy(
        {
            "name": "org-cfn-check",
            "resource": "aws.org-account",
            "filters": [
                {
                    "type": "cfn-stack",
                    "status": ["CREATE_COMPLETE", "UPDATE_COMPLETE"],
                    "stack_names": ["bob"],
                }
            ],
        }
    )
    cfn_stack = p.resource_manager.filters[0]
    s = boto3.Session()
    cfn = s.client("cloudformation")
    cfn.create_stack(StackName="bob", TemplateBody=template_body)
    result = cfn_stack.process_account_region({"Id": "123", "Name": "test-account"}, "us-east-1", s)
    assert result is False


def test_org_account_get_org_session(test):
    test.change_environment(LAMBDA_TASK_ROOT="/app")
    p = test.load_policy({"name": "org-cfn-check", "resource": "aws.org-account"})
    rm = p.resource_manager
    assert rm.get_org_session()


def test_org_account_account_role(test):
    p = test.load_policy({"name": "org-cfn-check", "resource": "aws.org-account"})
    assert p.resource_manager.account_config == {
        'org-account-role': 'OrganizationAccountAccessRole'
    }

    test.change_environment(AWS_CONTROL_TOWER_ORG="yes")

    p = test.load_policy({"name": "org-cfn-check", "resource": "aws.org-account"})
    assert p.resource_manager.account_config == {'org-account-role': 'AWSControlTowerExecution'}


class TestAccountSetProcess(org_module.ProcessAccountSet):
    return_value = True

    def process_account_region(self, account, region, session):
        if isinstance(self.return_value, Exception):
            raise self.return_value
        return self.return_value


@mock.patch("c7n.resources.org.account_session")
def test_process_account_set(account_session, test):
    p = test.load_policy({"name": "org-cfn-check", "resource": "aws.org-account"})

    processor = TestAccountSetProcess()
    processor.data = {}
    processor.type = "test-process"
    processor.manager = p.resource_manager
    p.resource_manager.executor_factory = MainThreadExecutor

    results = processor.process_account_set([{'Name': 'abc', 'Id': 'arn:1122'}])
    assert results == {'arn:1122': {'us-east-1': True}}

    processor.return_value = AttributeError()

    results = processor.process_account_set([{'Name': 'abc', 'Id': 'arn:1122'}])
    assert results == {'arn:1122': {'us-east-1': False}}

    account_session.side_effect = ClientError({}, "AssumeRole")
    processor.return_value = True

    results = processor.process_account_set([{'Name': 'abc', 'Id': 'arn:1122'}])
    assert not results


@mock.patch("c7n.resources.org.assumed_session")
def test_account_session(assumed_session):
    org_session = mock.MagicMock()
    assumed_session.return_value = 42
    s = org_module.account_session(org_session, {"Id": "112233"}, "role-name")
    assert s == 42
    s = org_module.account_session(
        org_session, {"Id": "112233"}, "arn:aws:iam::112233:role/role-name"
    )
    assert s == 42


@pytest.fixture()
def policy_org(org_tree):
    client = boto3.client("organizations")
    result = client.create_policy(
        Name="ec2-diet",
        Description="crash course dieting",
        Type='SERVICE_CONTROL_POLICY',
        Tags=[{'Key': 'Env', 'Value': 'ProdB'}],
        Content=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "RequireMicroInstanceType",
                        "Effect": "Deny",
                        "Action": "ec2:RunInstances",
                        "Resource": ["arn:aws:ec2:*:*:instance/*"],
                        "Condition": {"StringNotEquals": {"ec2:InstanceType": "t2.micro"}},
                    }
                ],
            }
        ),
    )
    pid = result['Policy']['PolicySummary']['Id']
    client.attach_policy(
        PolicyId=pid,
        TargetId=org_tree['dept_b']['Id'],
    )

    org_tree.update({'policy_ec2': pid})
    yield org_tree


def test_policy_query(policy_org, test):
    p = test.load_policy({"name": "org-cfn-check", "resource": "aws.org-policy"})
    assert p.resource_manager.parse_query() == {'Filter': 'SERVICE_CONTROL_POLICY'}
    resources = p.run()
    assert {r['Name'] for r in resources} == {'FullAWSAccess', 'ec2-diet'}
