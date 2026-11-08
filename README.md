# DocAgent

A LangChain agent that answers questions about confidential documents, with access enforced by cryptography rather than by the LLM.

- **AES-256-GCM** encrypts each document and detects tampering.
- **Envelope encryption** gives every document its own key (DEK), wrapped by a master key (KEK).
- **Ed25519-signed capabilities** (JWT) prove a user is allowed to read a document before its key is released.

The LLM never sees encryption keys or the raw document store. It can request a document, but it cannot grant itself access.

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -r requirements.txt
```

Create a `.env` file:

```env
ANTHROPIC_API_KEY=your-api-key
```

If you previously installed the `jwt` package, remove it first (`pip uninstall jwt`). It conflicts with PyJWT.

## Run

```bash
python app.py
```

Sign in as `alice` or `bob`, then ask a question, for example:

```text
What authentication mechanism does project-codex-1 use?
```

| User  | project-codex-1 | project-meteaverse-2 |
|-------|-----------------|----------------------|
| alice | Read            | Denied               |
| bob   | Denied          | Read                 |

## Test

```bash
python test_security.py
```

Checks authorized and denied access, forged capabilities, and tampered ciphertext and metadata. No API key needed.

## Project layout

| File | Purpose |
|------|---------|
| `app.py` | Entry point: sign-in stub and chat loop |
| `agent.py` | Builds the LangChain agent for an authenticated user |
| `document_tool.py` | Secure retrieval tool: authorize, verify, unwrap key, decrypt |
| `authorization.py` | Access policy plus Ed25519 capability issuing and verification |
| `key_manager.py` | Local KEK that wraps and unwraps document keys |
| `encryption.py` | AES-256-GCM document encryption |
| `document_store.py` | Encrypts the sample documents into the store |
| `test_security.py` | Security checks |
