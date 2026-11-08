import jwt
from cryptography.exceptions import InvalidTag
from langchain.tools import tool

from authorization import (
    authorize_document_access,
    verify_capability,
)
from encryption import decrypt_document


def secure_read_document(
    authenticated_subject: str,
    document_id: str,
    encrypted_document: dict,
    wrapped_dek: dict,
    key_manager,
) -> str:
    # Order matters: never unwrap the DEK before authorization is verified.

    # 1. Obtain authorization.
    capability = authorize_document_access(
        authenticated_subject,
        document_id,
    )

    # 2. Verify the signed capability.
    claims = verify_capability(
        capability,
        expected_subject=authenticated_subject,
        expected_resource=document_id,
    )

    # 3. Unwrap the document encryption key.
    dek = key_manager.unwrap_key(
        wrapped_dek,
        document_id,
    )

    # 4. Decrypt the document.
    plaintext = decrypt_document(
        encrypted_document,
        dek,
    )

    return plaintext.decode("utf-8")


def create_document_tool(
    authenticated_subject: str,
    document_store,
    key_manager,
):
    # authenticated_subject is supplied by the application, never by the LLM.
    # Create a new tool per user; never reuse this closure across users.

    @tool
    def read_document(document_id: str) -> str:
        """Read an authorized document using its document ID."""

        record = document_store.get(document_id)

        if record is None:
            return "Document not found."

        try:
            return secure_read_document(
                authenticated_subject=authenticated_subject,
                document_id=document_id,
                encrypted_document=record["encrypted"],
                wrapped_dek=record["wrapped_dek"],
                key_manager=key_manager,
            )

        except (PermissionError, jwt.InvalidTokenError):
            return "Access denied."

        except InvalidTag:
            return "Document integrity check failed."

    return read_document
