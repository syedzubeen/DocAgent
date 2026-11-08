import time
import uuid

import jwt

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ISSUER = "authorization-service"
AUDIENCE = "document-service"


# Tutorial only: a real application loads the private key from a
# protected key store so it persists across restarts.
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()


# ---------------------------------------------------------------------------
# Access policy
# ---------------------------------------------------------------------------

ACCESS_POLICIES = {
    "alice": {"project-codex-1"},
    "bob": {"project-meteaverse-2"},
}


def is_authorized(
    subject: str,
    document_id: str,
) -> bool:

    allowed_documents = ACCESS_POLICIES.get(
        subject,
        set(),
    )

    return document_id in allowed_documents


# ---------------------------------------------------------------------------
# Capability issuance and verification
# ---------------------------------------------------------------------------

def issue_capability(
    subject: str,
    resource: str,
    action: str,
) -> str:
    now = int(time.time())

    payload = {
        "sub": subject,
        "resource": resource,
        "action": action,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
    )


def verify_capability(
    token: str,
    expected_subject: str,
    expected_resource: str,
) -> dict:

    claims = jwt.decode(
        token,
        public_key,
        algorithms=["EdDSA"],
        issuer=ISSUER,
        audience=AUDIENCE,
        options={
            "require": [
                "sub",
                "resource",
                "action",
                "iat",
                "exp",
                "jti",
            ]
        },
    )

    if claims["sub"] != expected_subject:
        raise PermissionError("Invalid subject")

    if claims["resource"] != expected_resource:
        raise PermissionError("Invalid resource")

    if claims["action"] != "document:read":
        raise PermissionError("Invalid action")

    return claims


def authorize_document_access(
    subject: str,
    document_id: str,
) -> str:

    if not is_authorized(subject, document_id):
        raise PermissionError(
            "You are not authorized to access this document."
        )

    return issue_capability(
        subject=subject,
        resource=document_id,
        action="document:read",
    )
