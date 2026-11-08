"""Security checks from Steps 3 and 9 of the tutorial.

Run with:  python test_security.py
No LLM or API key is needed.
"""
import base64
import json

import jwt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from authorization import authorize_document_access, verify_capability
from document_store import build_document_store
from document_tool import create_document_tool
from encryption import decrypt_document, encrypt_document
from key_manager import LocalKeyManager


def test_encryption_round_trip():
    dek = AESGCM.generate_key(bit_length=256)
    document = b"Confidential project information"

    encrypted = encrypt_document(document, dek, "project-codex-1", 1)
    assert decrypt_document(encrypted, dek) == document


def test_tampered_ciphertext_is_rejected():
    dek = AESGCM.generate_key(bit_length=256)
    encrypted = encrypt_document(b"secret", dek, "project-codex-1", 1)

    encrypted["ciphertext"] = (
        encrypted["ciphertext"][:-1]
        + bytes([encrypted["ciphertext"][-1] ^ 1])
    )

    try:
        decrypt_document(encrypted, dek)
    except InvalidTag:
        return
    raise AssertionError("Tampered ciphertext was accepted")


def test_metadata_substitution_is_rejected():
    dek = AESGCM.generate_key(bit_length=256)
    encrypted = encrypt_document(b"secret", dek, "project-codex-1", 1)
    encrypted["document_id"] = "project-meteaverse-2"

    try:
        decrypt_document(encrypted, dek)
    except InvalidTag:
        return
    raise AssertionError("Substituted metadata was accepted")


def test_authorized_access():
    km = LocalKeyManager.generate()
    store = build_document_store(km)
    read = create_document_tool("alice", store, km)

    result = read.invoke({"document_id": "project-codex-1"})
    assert "OAuth 2.0" in result


def test_unauthorized_access():
    km = LocalKeyManager.generate()
    store = build_document_store(km)
    read = create_document_tool("alice", store, km)

    assert read.invoke({"document_id": "project-meteaverse-2"}) == "Access denied."


def test_modified_capability_is_rejected():
    token = authorize_document_access("alice", "project-codex-1")
    header, payload, signature = token.split(".")

    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    claims["resource"] = "project-meteaverse-2"
    forged_payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode()
    ).rstrip(b"=").decode()
    forged = f"{header}.{forged_payload}.{signature}"

    try:
        verify_capability(forged, "alice", "project-meteaverse-2")
    except jwt.InvalidSignatureError:
        return
    raise AssertionError("Modified capability was accepted")


def test_capability_for_other_resource_is_rejected():
    token = authorize_document_access("alice", "project-codex-1")

    try:
        verify_capability(token, "alice", "project-meteaverse-2")
    except PermissionError:
        return
    raise AssertionError("Capability was accepted for the wrong resource")


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\nAll {len(tests)} security checks passed.")
