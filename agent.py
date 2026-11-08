from langchain.agents import create_agent

from document_tool import create_document_tool


def build_agent(
    authenticated_subject: str,
    document_store,
    key_manager,
):

    document_tool = create_document_tool(
        authenticated_subject,
        document_store,
        key_manager,
    )

    return create_agent(
        model="anthropic:claude-sonnet-5-5",
        tools=[document_tool],
        system_prompt=(
            "You are a secure document assistant. "
            "Use the document retrieval tool to answer "
            "questions about documents. "
            "Never claim to have accessed a document "
            "unless the retrieval tool returned its content."
        ),
    )
