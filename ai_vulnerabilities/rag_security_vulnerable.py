"""Test cases for RAG security vulnerabilities."""
import chromadb
import pinecone
import faiss
from langchain.document_loaders import DirectoryLoader
from langchain.vectorstores import Chroma


def vulnerable_unvalidated_document_path(user_path):
    """Vulnerable: Loading documents from user-controlled path."""
    loader = DirectoryLoader(user_path)
    documents = loader.load()
    return documents


def vulnerable_vector_search_no_acl(query):
    """Vulnerable: Vector search without access control."""
    client = chromadb.Client()
    collection = client.get_collection("documents")
    results = collection.query(query_texts=[query], n_results=10)
    return results


def vulnerable_user_controlled_search_query(user_query):
    """Vulnerable: User-controlled vector search query."""
    vectorstore = Chroma(persist_directory="./db")
    results = vectorstore.similarity_search(user_query)
    return results


def vulnerable_chromadb_no_auth():
    """Vulnerable: ChromaDB without authentication."""
    client = chromadb.Client()
    collection = client.create_collection("sensitive_data")
    return collection


def vulnerable_pinecone_hardcoded_key():
    """Vulnerable: Hardcoded Pinecone API key."""
    pinecone.init(api_key="12345678-1234-1234-1234-123456789abc")
    index = pinecone.Index("my-index")
    return index


def vulnerable_faiss_index_from_path(index_path):
    """Vulnerable: Loading FAISS index from user path."""
    index = faiss.read_index(index_path)
    return index


def vulnerable_unfiltered_retrieved_content():
    """Vulnerable: Using retrieved documents without filtering."""
    from langchain.chains import RetrievalQA
    from langchain.llms import OpenAI

    vectorstore = Chroma(persist_directory="./db")
    retriever = vectorstore.as_retriever()

    qa_chain = RetrievalQA.from_chain_type(
        llm=OpenAI(),
        retriever=retriever
    )

    docs = retriever.get_relevant_documents("user query")
    return docs


def vulnerable_excessive_context_retrieval():
    """Vulnerable: Retrieving excessive context."""
    vectorstore = Chroma(persist_directory="./db")
    results = vectorstore.similarity_search("query", k=1000)
    return results


def vulnerable_user_controlled_embedding_model(model_name):
    """Vulnerable: User-controlled embedding model."""
    from langchain.embeddings import HuggingFaceEmbeddings
    embeddings = HuggingFaceEmbeddings(model_name=model_name)
    return embeddings


def vulnerable_llama_index_unvalidated_path(directory_path):
    """Vulnerable: LlamaIndex loading from user path."""
    from llama_index import SimpleDirectoryReader
    documents = SimpleDirectoryReader(directory_path).load_data()
    return documents


def vulnerable_weaviate_no_tenant_isolation():
    """Vulnerable: Weaviate without tenant isolation."""
    import weaviate
    client = weaviate.Client("http://localhost:8080")
    collection = client.collections.create("shared_collection")
    return collection


def safe_rag_with_access_control(query, user_id):
    """Safe: RAG with proper access control and validation."""
    import os
    from pathlib import Path

    ALLOWED_DIRECTORIES = ["/var/data/public"]
    base_path = Path("/var/data/public")

    if not base_path.exists():
        raise ValueError("Invalid base path")

    client = chromadb.Client()
    collection = client.get_collection("documents")

    results = collection.query(
        query_texts=[query],
        n_results=5,
        where={"user_id": user_id}
    )

    return results
