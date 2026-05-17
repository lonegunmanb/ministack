"""
Strict IAM authentication enforcement for MiniStack.

Activated by ``ENFORCE_IAM=1`` (or equivalently ``ENFORCE_IAM=true``).

When active, every request whose Authorization header carries an access key that
is **not** the bootstrap ``test`` key is checked:

1. The access key must exist in the IAM access-key store (``_access_keys``) and
   be ``Active``.  Missing / deleted / inactive keys return
   ``InvalidClientTokenId`` (HTTP 403), matching real AWS.

2. The requesting user's inline policies must grant the requested
   ``service:Action``.  No matching ``Allow`` statement → ``AccessDenied``
   (HTTP 403).

Bootstrap key (``test`` / ``BOOTSTRAP_KEYS``):
  Always allowed regardless of mode.  Needed for the tutorial's Admin workspace
  and for the first IAM user / access-key creation.

STS actions:
  ``GetCallerIdentity`` (and the other STS calls) are always permitted for any
  valid key because real AWS does not require an explicit policy Allow for them.

The module also exposes a ``_request_iam_user_ctx`` context variable that is
set by ``check_request`` when the caller is identified as a named IAM user.
``iam.py`` reads this to implement the "``GetUser`` with no ``UserName``"
behaviour that Vault / Terraform's credential-validation path relies on.
"""

import contextvars
import fnmatch
import json
import os
import uuid
from urllib.parse import parse_qs

# ---------------------------------------------------------------------------
# Module-level runtime flag — can be toggled via /_ministack/config.
# ---------------------------------------------------------------------------

ENFORCE_IAM: bool = os.environ.get("ENFORCE_IAM", "0").lower() in ("1", "true", "yes")

# ---------------------------------------------------------------------------
# Access keys that unconditionally bypass IAM enforcement.
# The bootstrap ``test`` key must remain usable as an admin/root credential
# so the tutorial can create the first Vault-owned IAM user.
# ---------------------------------------------------------------------------

BOOTSTRAP_KEYS: frozenset = frozenset({"test"})

# ---------------------------------------------------------------------------
# Per-request context: the IAM user name associated with the current key.
# Set in ``check_request``; read by ``iam._get_user`` when UserName is omitted.
# ---------------------------------------------------------------------------

_request_iam_user_ctx: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_request_iam_user_ctx", default=""
)


def get_request_iam_user() -> str:
    """Return the IAM user name for the current request (empty string if none)."""
    return _request_iam_user_ctx.get()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _enforce_iam_active() -> bool:
    return ENFORCE_IAM


def _extract_action(service: str, headers: dict, body: bytes, query_params: dict) -> str:
    """Return the ``service:Action`` string for this request, or ``""``."""
    # 1. Query-string ?Action=…
    raw = query_params.get("Action", "")
    if isinstance(raw, list):
        raw = raw[0] if raw else ""
    if raw:
        return f"{service}:{raw}"

    # 2. Form-encoded body (POST to IAM / STS / EC2)
    if body:
        try:
            bp = parse_qs(body.decode("utf-8", errors="replace"))
            raw = bp.get("Action", [""])[0]
            if raw:
                return f"{service}:{raw}"
        except Exception:
            pass

    # 3. X-Amz-Target header (JSON-protocol services like DynamoDB)
    target = headers.get("x-amz-target", "")
    if "." in target:
        return f"{service}:{target.rsplit('.', 1)[-1]}"

    # 4. JSON body { "Action": "…" } (some newer SDK protocol shapes)
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict) and "Action" in parsed:
                return f"{service}:{parsed['Action']}"
        except Exception:
            pass

    return ""


def _policy_allows(user_policies: dict, service_action: str) -> bool:
    """Return ``True`` if any Allow statement in *user_policies* covers *service_action*.

    Supports:
    - Exact match: ``"iam:CreateUser"``
    - Trailing wildcard: ``"iam:*"``, ``"ec2:Describe*"``
    - Global wildcard: ``"*"``
    - Action lists: ``["iam:*", "sts:GetCallerIdentity"]``

    Only ``Effect: Allow`` statements are honoured; explicit ``Deny`` wins
    if it ever appears, but the tutorial only requires Allow.
    """
    deny_match = False
    allow_match = False

    for _pname, policy_doc in user_policies.items():
        if isinstance(policy_doc, (bytes, bytearray)):
            try:
                doc = json.loads(policy_doc.decode("utf-8"))
            except Exception:
                continue
        elif isinstance(policy_doc, str):
            try:
                doc = json.loads(policy_doc)
            except Exception:
                continue
        else:
            doc = policy_doc

        if not isinstance(doc, dict):
            continue

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "Deny")
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            matched = any(
                act == "*" or fnmatch.fnmatch(service_action.lower(), act.lower())
                for act in actions
            )
            if not matched:
                continue

            if effect == "Allow":
                allow_match = True
            elif effect == "Deny":
                deny_match = True

    # Explicit Deny wins over Allow (partial AWS IAM semantics).
    if deny_match:
        return False
    return allow_match


def _xml_403(code: str, message: str) -> tuple:
    """Build a 403 XML error response in IAM-namespace format."""
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">\n'
        "  <Error>\n"
        f"    <Code>{code}</Code>\n"
        f"    <Message>{message}</Message>\n"
        "  </Error>\n"
        f"  <RequestId>{uuid.uuid4()}</RequestId>\n"
        "</ErrorResponse>"
    )
    return 403, {"Content-Type": "application/xml"}, body.encode()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_request(
    service: str,
    method: str,
    path: str,
    headers: dict,
    body: bytes,
    query_params: dict,
) -> "tuple | None":
    """Validate IAM auth for the incoming request.

    Returns:
        ``None``  — request is allowed; proceed normally.
        ``tuple`` — ``(status, headers, body)`` error response to return to the
                    caller instead of dispatching to the service handler.
    """
    if not _enforce_iam_active():
        return None

    # Internal admin / health endpoints are always allowed.
    if path.startswith("/_"):
        return None

    # Extract the access key from the Authorization header.
    auth = headers.get("authorization", "")
    access_key = ""
    if auth and "Credential=" in auth:
        try:
            access_key = auth.split("Credential=")[1].split("/")[0]
        except Exception:
            pass

    # No credentials, or bootstrap key → always pass.
    if not access_key or access_key in BOOTSTRAP_KEYS:
        _request_iam_user_ctx.set("")
        return None

    # Lazy import to avoid circular-import issues at module load time.
    from ministack.services.iam import (  # noqa: PLC0415
        _access_keys,
        _user_inline_policies,
        _users,
    )

    key_record = _access_keys.get(access_key)
    if key_record is None:
        return _xml_403(
            "InvalidClientTokenId",
            "The security token included in the request is invalid.",
        )

    if key_record.get("Status") != "Active":
        return _xml_403(
            "InvalidClientTokenId",
            "The security token included in the request has been revoked.",
        )

    user_name = key_record.get("UserName", "")

    # Check that the owning IAM user still exists (guards against the user
    # being deleted without first deleting their access keys).
    if user_name and user_name not in _users:
        return _xml_403(
            "InvalidClientTokenId",
            "The user associated with this security token no longer exists.",
        )

    # Stash the resolved user name for downstream consumers (e.g. GetUser).
    _request_iam_user_ctx.set(user_name)

    # STS actions are always permitted for valid keys (mirrors real AWS
    # behaviour: GetCallerIdentity, AssumeRole, etc. need no explicit policy).
    if service == "sts":
        return None

    # Determine the service:Action being requested.
    action = _extract_action(service, headers, body, query_params)
    if not action:
        # Cannot determine the action → allow (avoids breaking services we
        # haven't mapped yet while keeping the enforcement meaningful for the
        # tutorial services: IAM, STS, EC2).
        return None

    # Look up the user's inline policies.
    user_policies = _user_inline_policies.get(user_name) or {}

    from ministack.core.responses import get_account_id  # noqa: PLC0415
    account_id = get_account_id()

    if not user_policies:
        return _xml_403(
            "AccessDenied",
            f"User: arn:aws:iam::{account_id}:user/{user_name} is not authorized "
            f"to perform: {action} (no policies attached)",
        )

    if _policy_allows(user_policies, action):
        return None

    return _xml_403(
        "AccessDenied",
        f"User: arn:aws:iam::{account_id}:user/{user_name} is not authorized "
        f"to perform: {action}",
    )
