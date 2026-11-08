from dotenv import load_dotenv

load_dotenv()

from agent import build_agent  # noqa: E402
from document_store import build_document_store  # noqa: E402
from key_manager import LocalKeyManager  # noqa: E402


def get_authenticated_subject() -> str:
    """Stand-in for a real authentication layer.

    In a real deployment, the identity comes from a validated session or
    token, never from a user-typed string or an LLM-generated argument.
    """
    return input("Sign in as (alice / bob): ").strip().lower()


def main():
    key_manager = LocalKeyManager.load_or_create()
    document_store = build_document_store(key_manager)

    subject = get_authenticated_subject()
    agent = build_agent(subject, document_store, key_manager)

    while True:
        question = input("\nAsk a question: ")
        if question.lower() in {"exit", "quit"}:
            break

        result = agent.invoke({
            "messages": [
                {"role": "user", "content": question}
            ]
        })

        print("\nAnswer:")
        print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
