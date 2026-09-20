"""
TrustRAG Document Ingestion Pipeline
Loads documents from each clearance folder, splits them into semantic chunks,
tags them with security metadata (clearance_required, department, source),
and indexes them into the ChromaDB 'enterprise_docs' collection.
"""

import os
from pathlib import Path
from typing import List, Dict, Any

import chromadb
from chromadb.utils import embedding_functions

import config


def get_embedding_function():
    """
    Returns the appropriate embedding function:
    - OpenAI embeddings if OPENAI_API_KEY is configured
    - Default ONNX all-MiniLM-L6-v2 embeddings (works completely offline)
    """
    if config.OPENAI_API_KEY and not config.OPENAI_API_KEY.startswith("your-"):
        try:
            return embedding_functions.OpenAIEmbeddingFunction(
                api_key=config.OPENAI_API_KEY,
                model_name=config.EMBEDDING_MODEL
            )
        except Exception as e:
            print(f"[Warning] OpenAI embedding init failed: {e}. Falling back to local embeddings.")
    
    # Built-in lightweight local embedding function (no API key required)
    return embedding_functions.DefaultEmbeddingFunction()


def get_chroma_client():
    """Returns a persistent ChromaDB client."""
    os.makedirs(config.CHROMA_PERSIST_DIR, exist_ok=True)
    return chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)


def chunk_text(text: str, chunk_size: int = 500, chunk_overlap: int = 50) -> List[str]:
    """
    Splits text into readable chunks with slight overlap by sections/paragraphs.
    """
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks = []
    
    for p in paragraphs:
        if len(p) <= chunk_size:
            chunks.append(p)
        else:
            # Sub-split long paragraphs
            words = p.split(" ")
            current = []
            current_len = 0
            for w in words:
                if current_len + len(w) + 1 > chunk_size and current:
                    chunks.append(" ".join(current))
                    # Keep trailing words matching requested character overlap
                    overlap_words = []
                    overlap_len = 0
                    for rev_w in reversed(current):
                        if overlap_len + len(rev_w) + 1 <= chunk_overlap:
                            overlap_words.insert(0, rev_w)
                            overlap_len += len(rev_w) + 1
                        else:
                            break
                    current = overlap_words + [w]
                    current_len = sum(len(x) + 1 for x in current)
                else:
                    current.append(w)
                    current_len += len(w) + 1
            if current:
                chunks.append(" ".join(current))
                
    return chunks


def ingest_documents(force_reset: bool = True) -> Dict[str, Any]:
    """
    Scans the clearance folders, extracts text, tags each chunk with metadata,
    and inserts into the ChromaDB collection.
    """
    client = get_chroma_client()
    embed_fn = get_embedding_function()

    # Reset or get existing collection
    if force_reset:
        try:
            client.delete_collection(name=config.CHROMA_DOCS_COLLECTION)
            print(f"[Ingest] Cleared old collection: '{config.CHROMA_DOCS_COLLECTION}'")
        except Exception:
            pass

    collection = client.get_or_create_collection(
        name=config.CHROMA_DOCS_COLLECTION,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"}
    )

    documents_to_add = []
    metadatas_to_add = []
    ids_to_add = []

    total_files = 0
    total_chunks = 0

    # Iterate through all 4 clearance levels
    for level, level_info in config.CLEARANCE_LEVELS.items():
        doc_dir = Path(level_info["allowed_data_dir"])
        if not doc_dir.exists():
            continue

        for file_path in doc_dir.glob("*.txt"):
            total_files += 1
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            chunks = chunk_text(content)
            for idx, chunk in enumerate(chunks):
                chunk_id = f"lvl{level}_{file_path.stem}_chunk{idx}"
                meta = {
                    "clearance_required": int(level),
                    "clearance_name": level_info["name"],
                    "source": file_path.name,
                    "chunk_index": idx
                }
                documents_to_add.append(chunk)
                metadatas_to_add.append(meta)
                ids_to_add.append(chunk_id)
                total_chunks += 1

    if documents_to_add:
        collection.add(
            documents=documents_to_add,
            metadatas=metadatas_to_add,
            ids=ids_to_add
        )
        print(f"[Ingest] Successfully ingested {total_chunks} chunks from {total_files} files across 4 clearance tiers.")

    return {
        "status": "success",
        "total_files": total_files,
        "total_chunks": total_chunks,
        "collection_count": collection.count()
    }


def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    """Extracts raw text from .txt or .pdf files."""
    ext = Path(filename).suffix.lower()
    if ext == ".txt":
        return file_bytes.decode("utf-8", errors="ignore")
    elif ext == ".pdf":
        try:
            import fitz  # PyMuPDF
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            pages_text = [page.get_text() for page in doc]
            return "\n\n".join(pages_text)
        except Exception as e:
            print(f"[PDF Extract Error] {e}")
            return ""
    else:
        return file_bytes.decode("utf-8", errors="ignore")


def ingest_single_document(
    file_bytes: bytes,
    filename: str,
    target_clearance: int,
    username: str = "admin"
) -> Dict[str, Any]:
    """
    Ingests a single uploaded document (PDF/TXT), tags it with clearance metadata,
    archives it to the corresponding folder, indexes chunks into ChromaDB, and logs to audit.
    """
    import time
    import db

    text = extract_text_from_file(file_bytes, filename)
    if not text.strip():
        return {"status": "error", "message": "File is empty or no text could be extracted."}

    chunks = chunk_text(text)
    if not chunks:
        return {"status": "error", "message": "No valid text chunks generated from file."}

    client = get_chroma_client()
    embed_fn = get_embedding_function()
    collection = client.get_or_create_collection(
        name=config.CHROMA_DOCS_COLLECTION,
        embedding_function=embed_fn,
        metadata={"hnsw:space": "cosine"}
    )

    clean_stem = Path(filename).stem.replace(" ", "_").lower()
    documents_to_add = []
    metadatas_to_add = []
    ids_to_add = []

    level_info = config.CLEARANCE_LEVELS.get(target_clearance, {})
    clearance_name = level_info.get("name", f"Level {target_clearance}")

    timestamp_suffix = int(time.time())
    for idx, chunk in enumerate(chunks):
        chunk_id = f"lvl{target_clearance}_{clean_stem}_{timestamp_suffix}_chk{idx}"
        meta = {
            "clearance_required": int(target_clearance),
            "clearance_name": clearance_name,
            "source": filename,
            "chunk_index": idx
        }
        documents_to_add.append(chunk)
        metadatas_to_add.append(meta)
        ids_to_add.append(chunk_id)

    collection.add(
        documents=documents_to_add,
        metadatas=metadatas_to_add,
        ids=ids_to_add
    )

    # Save to disk in appropriate clearance folder
    target_dir = Path(level_info.get("allowed_data_dir", config.BASE_DIR / "data" / f"level_{target_clearance}"))
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / filename
    with open(target_path, "wb") as f:
        f.write(file_bytes)

    # Log ingestion in audit table
    db.log_audit_event(
        username=username,
        clearance_level=target_clearance,
        prompt=f"[Document Ingestion] Uploaded '{filename}' to {clearance_name}",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=len(chunks),
        response=f"Successfully indexed {len(chunks)} chunk(s).",
        latency_ms=0
    )

    return {
        "status": "success",
        "filename": filename,
        "chunks_count": len(chunks),
        "target_clearance": target_clearance,
        "clearance_name": clearance_name,
        "saved_path": str(target_path),
        "preview_chunks": chunks[:2]
    }


if __name__ == "__main__":
    result = ingest_documents(force_reset=True)
    print("Ingestion Result:", result)

