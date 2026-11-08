import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_document(
    plaintext: bytes,
    dek: bytes,
    document_id: str,
    version: int,
) -> dict:
    nonce = os.urandom(12)

    aad = f"{document_id}:{version}".encode()

    aesgcm = AESGCM(dek)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad,
    )

    return {
        "document_id": document_id,
        "version": version,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }


def decrypt_document(
    encrypted_document: dict,
    dek: bytes,
) -> bytes:
    aad = (
        f"{encrypted_document['document_id']}:"
        f"{encrypted_document['version']}"
    ).encode()

    aesgcm = AESGCM(dek)

    return aesgcm.decrypt(
        encrypted_document["nonce"],
        encrypted_document["ciphertext"],
        aad,
    )
