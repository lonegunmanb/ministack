"""
Integration tests for strict IAM authentication enforcement (ENFORCE_IAM=1).

These tests toggle ENFORCE_IAM mode via the /_ministack/config endpoint so
they can run against the shared test server without requiring the server to
have been started with ENFORCE_IAM=1.  Every test that needs strict mode
calls ``enable_iam_enforcement`` and tears it down with ``disable_iam_enforcement``.

Coverage:
- bootstrap ``test/test`` can create IAM resources when ENFORCE_IAM=1;
- a request signed with a newly-created access key succeeds when its user
  policy allows the requested action;
- ``iam:GetUser`` without ``UserName`` returns the current signed-in IAM user;
- deleting the access key makes later requests fail with an invalid-token 403;
- a user with only ``iam:*`` can call IAM but cannot call EC2;
- a user with ``ec2:*`` can call ``DescribeAvailabilityZones``, ``RunInstances``,
  ``DescribeInstances``, and ``TerminateInstances``;
- wildcard policy matching works for ``iam:*``, ``ec2:*``, ``ec2:Describe*``;
- regression: deleted access key fails even after the owning user is gone.
"""

import json
import os
import urllib.request
import uuid as _uuid_mod

import boto3
import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = os.environ.get("MINISTACK_ENDPOINT", "http://localhost:4566")
REGION = "us-east-1"

_admin_kwargs = dict(
    endpoint_url=ENDPOINT,
    aws_access_key_id="test",
    aws_secret_access_key="test",
    region_name=REGION,
)
_admin_config = Config(region_name=REGION, retries={"mode": "standard"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ministack_config(settings: dict) -> None:
    req = urllib.request.Request(
        f"{ENDPOINT}/_ministack/config",
        data=json.dumps(settings).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=5)


def enable_iam_enforcement() -> None:
    _ministack_config({"iam_auth.ENFORCE_IAM": True})


def disable_iam_enforcement() -> None:
    _ministack_config({"iam_auth.ENFORCE_IAM": False})


def _admin_iam():
    return boto3.client("iam", **_admin_kwargs, config=_admin_config)


def _admin_ec2():
    return boto3.client("ec2", **_admin_kwargs, config=_admin_config)


def _client_with_key(service: str, key_id: str, secret: str):
    """Return a boto3 client using the given IAM-created key pair."""
    return boto3.client(
        service,
        endpoint_url=ENDPOINT,
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=REGION,
        config=Config(region_name=REGION, retries={"mode": "standard"}),
    )


def _unique(prefix: str) -> str:
    return f"{prefix}-{_uuid_mod.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _enforce_iam_scope():
    """Each test in this module runs with ENFORCE_IAM enabled, and the flag
    is restored to False after the test completes."""
    enable_iam_enforcement()
    try:
        yield
    finally:
        disable_iam_enforcement()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBootstrapCredentials:
    def test_bootstrap_can_create_user(self):
        """Bootstrap test/test must work as admin when ENFORCE_IAM=1."""
        iam = _admin_iam()
        uname = _unique("bs-user")
        resp = iam.create_user(UserName=uname)
        assert resp["User"]["UserName"] == uname
        iam.delete_user(UserName=uname)

    def test_bootstrap_can_create_access_key(self):
        iam = _admin_iam()
        uname = _unique("bs-ak-user")
        iam.create_user(UserName=uname)
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        assert key["AccessKeyId"].startswith("AKIA")
        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user(UserName=uname)

    def test_bootstrap_can_put_user_policy(self):
        iam = _admin_iam()
        uname = _unique("bs-pol-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="test-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        iam.delete_user_policy(UserName=uname, PolicyName="test-pol")
        iam.delete_user(UserName=uname)


class TestNewKeySucceeds:
    def test_key_with_iam_star_can_call_iam(self):
        """A freshly-created key whose user has iam:* can call IAM actions."""
        iam = _admin_iam()
        uname = _unique("iam-star-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="iam-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]

        # Use new key to list users — must succeed
        user_iam = _client_with_key("iam", key["AccessKeyId"], key["SecretAccessKey"])
        resp = user_iam.list_users()
        assert "Users" in resp

        # Cleanup (use admin key for teardown)
        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="iam-pol")
        iam.delete_user(UserName=uname)


class TestGetUserWithoutUsername:
    def test_get_user_no_username_returns_current_user(self):
        """GetUser with no UserName should return the currently signed-in user."""
        iam = _admin_iam()
        uname = _unique("gu-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="iam-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]

        user_iam = _client_with_key("iam", key["AccessKeyId"], key["SecretAccessKey"])
        resp = user_iam.get_user()  # No UserName argument
        returned_name = resp["User"]["UserName"]
        assert returned_name == uname, (
            f"Expected GetUser() to return '{uname}', got '{returned_name}'"
        )

        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="iam-pol")
        iam.delete_user(UserName=uname)


class TestDeletedKeyFails:
    def test_deleted_key_returns_invalid_token(self):
        """Requests signed with a deleted access key must fail with InvalidClientTokenId."""
        iam = _admin_iam()
        uname = _unique("del-key-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="iam-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        key_id = key["AccessKeyId"]

        # Verify the key works first
        user_iam = _client_with_key("iam", key_id, key["SecretAccessKey"])
        user_iam.list_users()  # must not raise

        # Delete the key
        iam.delete_access_key(UserName=uname, AccessKeyId=key_id)

        # Subsequent request with the same key must fail
        with pytest.raises(ClientError) as exc:
            user_iam.list_users()
        code = exc.value.response["Error"]["Code"]
        assert code in ("InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException"), (
            f"Expected InvalidClientTokenId-style error, got: {code}"
        )

        iam.delete_user_policy(UserName=uname, PolicyName="iam-pol")
        iam.delete_user(UserName=uname)

    def test_deleted_user_access_key_fails(self):
        """After deleting the IAM user (which requires deleting keys first),
        a stale key reference should no longer be valid."""
        iam = _admin_iam()
        uname = _unique("del-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="iam-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        key_id = key["AccessKeyId"]
        key_secret = key["SecretAccessKey"]

        user_iam = _client_with_key("iam", key_id, key_secret)
        user_iam.list_users()  # sanity check

        # Delete the key, then delete the user
        iam.delete_access_key(UserName=uname, AccessKeyId=key_id)
        iam.delete_user_policy(UserName=uname, PolicyName="iam-pol")
        iam.delete_user(UserName=uname)

        # Key no longer exists → any service call must fail
        with pytest.raises(ClientError) as exc:
            user_iam.list_users()
        code = exc.value.response["Error"]["Code"]
        assert code in ("InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException")


class TestIamOnlyCannotCallEc2:
    def test_iam_star_cannot_describe_azs(self):
        """A user with only iam:* must not be able to call EC2."""
        iam = _admin_iam()
        uname = _unique("iam-only-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="iam-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]

        ec2 = _client_with_key("ec2", key["AccessKeyId"], key["SecretAccessKey"])
        with pytest.raises(ClientError) as exc:
            ec2.describe_availability_zones()
        code = exc.value.response["Error"]["Code"]
        assert code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"), (
            f"Expected AccessDenied-style error, got: {code}"
        )

        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="iam-pol")
        iam.delete_user(UserName=uname)


class TestEc2StarCanCallEc2:
    def test_ec2_star_can_describe_azs(self):
        """A user with ec2:* can call DescribeAvailabilityZones."""
        iam = _admin_iam()
        uname = _unique("ec2-star-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="ec2-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]

        ec2 = _client_with_key("ec2", key["AccessKeyId"], key["SecretAccessKey"])
        resp = ec2.describe_availability_zones()
        assert resp["AvailabilityZones"]

        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="ec2-pol")
        iam.delete_user(UserName=uname)

    def test_ec2_star_can_run_and_terminate_instances(self):
        """A user with ec2:* can run, describe, and terminate instances."""
        iam = _admin_iam()
        uname = _unique("ec2-full-user")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="ec2-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        ec2 = _client_with_key("ec2", key["AccessKeyId"], key["SecretAccessKey"])

        # RunInstances
        run_resp = ec2.run_instances(
            ImageId="ami-ff0fea8310f3",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )
        instance_id = run_resp["Instances"][0]["InstanceId"]

        # DescribeInstances
        desc_resp = ec2.describe_instances(InstanceIds=[instance_id])
        assert desc_resp["Reservations"]

        # TerminateInstances
        ec2.terminate_instances(InstanceIds=[instance_id])

        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="ec2-pol")
        iam.delete_user(UserName=uname)


class TestWildcardPolicyMatching:
    def test_iam_star_matches_list_users(self):
        """iam:* wildcard must match iam:ListUsers."""
        iam = _admin_iam()
        uname = _unique("wc-iam")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="p",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        user_iam = _client_with_key("iam", key["AccessKeyId"], key["SecretAccessKey"])
        user_iam.list_users()
        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="p")
        iam.delete_user(UserName=uname)

    def test_ec2_describe_star_matches_describe_azs(self):
        """ec2:Describe* must match ec2:DescribeAvailabilityZones."""
        iam = _admin_iam()
        uname = _unique("wc-ec2-desc")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="p",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        ec2 = _client_with_key("ec2", key["AccessKeyId"], key["SecretAccessKey"])
        resp = ec2.describe_availability_zones()
        assert resp["AvailabilityZones"]
        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="p")
        iam.delete_user(UserName=uname)

    def test_ec2_describe_star_does_not_match_run_instances(self):
        """ec2:Describe* must NOT match ec2:RunInstances."""
        iam = _admin_iam()
        uname = _unique("wc-ec2-norun")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="p",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        ec2 = _client_with_key("ec2", key["AccessKeyId"], key["SecretAccessKey"])
        with pytest.raises(ClientError) as exc:
            ec2.run_instances(
                ImageId="ami-ff0fea8310f3",
                InstanceType="t2.micro",
                MinCount=1,
                MaxCount=1,
            )
        code = exc.value.response["Error"]["Code"]
        assert code in ("AccessDenied", "UnauthorizedOperation"), (
            f"Expected AccessDenied-style error for RunInstances, got: {code}"
        )
        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="p")
        iam.delete_user(UserName=uname)

    def test_ec2_star_wildcard(self):
        """ec2:* must match ec2:DescribeAvailabilityZones and ec2:RunInstances."""
        iam = _admin_iam()
        uname = _unique("wc-ec2-star")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="p",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        ec2 = _client_with_key("ec2", key["AccessKeyId"], key["SecretAccessKey"])

        resp = ec2.describe_availability_zones()
        assert resp["AvailabilityZones"]

        run_resp = ec2.run_instances(
            ImageId="ami-ff0fea8310f3",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
        )
        instance_id = run_resp["Instances"][0]["InstanceId"]
        ec2.terminate_instances(InstanceIds=[instance_id])

        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="p")
        iam.delete_user(UserName=uname)


class TestRegressionStaleKeyAfterRevoke:
    """Regression guard for the LocalStack gap: a key deleted (or its user
    deleted) must be rejected on subsequent requests.

    This is the critical path that allows the tutorial's fixed-TTL failure
    scenario: after Vault revokes the dynamic lease, any EC2 call signed
    with the stale key must fail.
    """

    def test_stale_key_fails_after_key_deletion(self):
        """create key → allow ec2 → delete key → ec2 fails."""
        iam = _admin_iam()
        uname = _unique("regress-del-key")
        iam.create_user(UserName=uname)
        iam.put_user_policy(
            UserName=uname,
            PolicyName="ec2-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]
        key_id = key["AccessKeyId"]

        ec2 = _client_with_key("ec2", key_id, key["SecretAccessKey"])

        # First call: must succeed
        resp = ec2.describe_availability_zones()
        assert resp["AvailabilityZones"]

        # Delete the access key (simulating Vault lease revocation)
        iam.delete_access_key(UserName=uname, AccessKeyId=key_id)

        # Second call with the same stale key: must fail
        with pytest.raises(ClientError) as exc:
            ec2.describe_availability_zones()
        code = exc.value.response["Error"]["Code"]
        assert code in ("InvalidClientTokenId", "AuthFailure", "UnrecognizedClientException"), (
            f"Expected stale-key rejection, got: {code}"
        )

        iam.delete_user_policy(UserName=uname, PolicyName="ec2-pol")
        iam.delete_user(UserName=uname)


class TestStsAlwaysAllowed:
    def test_get_caller_identity_with_iam_key(self):
        """GetCallerIdentity must work for IAM-created keys with no explicit STS policy."""
        iam = _admin_iam()
        uname = _unique("sts-ci-user")
        iam.create_user(UserName=uname)
        # Only grant iam:* — no sts:* policy
        iam.put_user_policy(
            UserName=uname,
            PolicyName="iam-pol",
            PolicyDocument=json.dumps(
                {"Version": "2012-10-17",
                 "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
            ),
        )
        key = iam.create_access_key(UserName=uname)["AccessKey"]

        sts = _client_with_key("sts", key["AccessKeyId"], key["SecretAccessKey"])
        resp = sts.get_caller_identity()
        # Must return the IAM user's ARN
        assert uname in resp["Arn"], (
            f"Expected GetCallerIdentity to return user ARN containing '{uname}', "
            f"got: {resp['Arn']}"
        )

        iam.delete_access_key(UserName=uname, AccessKeyId=key["AccessKeyId"])
        iam.delete_user_policy(UserName=uname, PolicyName="iam-pol")
        iam.delete_user(UserName=uname)
