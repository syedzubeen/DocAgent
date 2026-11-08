from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from encryption import encrypt_document


# Plaintext seed data. It is encrypted when the store is built and
# the agent only ever sees it through the secure retrieval tool.
SEED_DOCUMENTS = {
    "project-codex-1": """
    Project Codex uses OAuth 2.0 for API authentication.
    The backend consists of Go microservices. The deployment platform is Kubernetes.
    """,
    "project-meteaverse-2": """
    Project Meta Verse uses mutual TLS for service authentication. The application
    runs on a private cloud infrastructure.
    """,
}


def build_document_store(key_manager, documents=None, version: int = 1) -> dict:
    """Encrypt each document with its own DEK and store only the wrapped DEK.

    Each record holds the encrypted document (document ID, version, nonce,
    ciphertext with auth tag) and the DEK wrapped by the KEK. No plaintext
    keys are stored.
    """
    documents = documents if documents is not None else SEED_DOCUMENTS
    store = {}

    for document_id, text in documents.items():
        dek = AESGCM.generate_key(bit_length=256)

        store[document_id] = {
            "encrypted": encrypt_document(
                text.encode("utf-8"),
                dek,
                document_id,
                version,
            ),
            "wrapped_dek": key_manager.wrap_key(dek, document_id),
        }

    return store
