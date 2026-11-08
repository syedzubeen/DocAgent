import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class LocalKeyManager:
    """Teaching implementation of a key manager.

    In production, replace this with an enterprise KMS or HSM.
    """

    def __init__(self, kek: bytes):
        self.kek = kek
        self.aesgcm = AESGCM(kek)

    @classmethod
    def generate(cls):
        kek = AESGCM.generate_key(bit_length=256)
        return cls(kek)

    @classmethod
    def load_or_create(cls, path: str = ".keys/kek.bin"):
        """Load the KEK from disk, creating it on first run.

        Generating a new KEK on every start would make previously
        wrapped DEKs impossible to unwrap, so the KEK is persisted.
        Keep this file out of Git and never put it in a prompt.
        """
        if os.path.exists(path):
            with open(path, "rb") as f:
                return cls(f.read())

        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        kek = AESGCM.generate_key(bit_length=256)
        with open(path, "wb") as f:
            f.write(kek)
        return cls(kek)

    def wrap_key(self, dek: bytes, document_id: str) -> dict:
        nonce = os.urandom(12)

        aad = document_id.encode()

        wrapped_key = self.aesgcm.encrypt(
            nonce,
            dek,
            aad,
        )

        return {
            "nonce": nonce,
            "wrapped_key": wrapped_key,
        }

    def unwrap_key(
        self,
        wrapped_key: dict,
        document_id: str,
    ) -> bytes:
        return self.aesgcm.decrypt(
            wrapped_key["nonce"],
            wrapped_key["wrapped_key"],
            document_id.encode(),
        )
