from xml.etree import ElementTree as ET

from ministack.services import iam_auth


def _auth_headers(access_key: str) -> dict:
    return {
        "authorization": (
            "AWS4-HMAC-SHA256 "
            f"Credential={access_key}/20260517/us-east-1/ec2/aws4_request, "
            "SignedHeaders=host;x-amz-date, Signature=deadbeef"
        )
    }


def test_ec2_auth_failure_uses_ec2_query_error_shape(monkeypatch):
    monkeypatch.setattr(iam_auth, "ENFORCE_IAM", True)

    status, headers, body = iam_auth.check_request(
        "ec2",
        "POST",
        "/",
        _auth_headers("AKIASTALE"),
        b"Action=DescribeAvailabilityZones&Version=2016-11-15",
        {},
    )

    assert status == 403
    assert headers["Content-Type"] == "application/xml"
    root = ET.fromstring(body)
    assert root.tag == "Response"
    assert root.findtext("./Errors/Error/Code") == "InvalidClientTokenId"
    assert root.find("./RequestID") is not None


def test_iam_auth_failure_keeps_iam_error_shape(monkeypatch):
    monkeypatch.setattr(iam_auth, "ENFORCE_IAM", True)

    status, _headers, body = iam_auth.check_request(
        "iam",
        "POST",
        "/",
        _auth_headers("AKIASTALE"),
        b"Action=ListUsers&Version=2010-05-08",
        {},
    )

    assert status == 403
    root = ET.fromstring(body)
    assert root.tag == "{https://iam.amazonaws.com/doc/2010-05-08/}ErrorResponse"
    assert root.findtext(".//{https://iam.amazonaws.com/doc/2010-05-08/}Code") == "InvalidClientTokenId"
