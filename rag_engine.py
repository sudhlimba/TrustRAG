"""
TrustRAG Secure Retrieval-Augmented Generation Engine
Implements zero-trust hierarchical vector retrieval, prompt firewall inspection,
LLM synthesis with local/OpenAI failover, output secret scrubbing, and compliance audit logging.
"""

import time
import re
import threading
from collections import defaultdict
from typing import Dict, Any, List, Optional, Tuple

import config
import db
from firewall import is_attack
from ingest import get_chroma_client, get_embedding_function

# Query Rate Limiter (10 req/min per user)
_RATE_LOCK = threading.Lock()
_USER_QUERY_TIMES = defaultdict(list)


def is_query_rate_limited(username: str, max_per_minute: int = 10) -> Tuple[bool, int]:
    """
    Evaluates whether a user exceeded the query rate limit within a 60-second sliding window.
    Returns (is_limited, seconds_to_wait).
    """
    now = time.time()
    with _RATE_LOCK:
        history = [t for t in _USER_QUERY_TIMES[username] if now - t < 60]
        if len(history) >= max_per_minute:
            oldest = history[0]
            wait_sec = max(1, int(60 - (now - oldest)) + 1)
            _USER_QUERY_TIMES[username] = history
            return True, wait_sec
        history.append(now)
        _USER_QUERY_TIMES[username] = history
        return False, 0

# Output Secret Scrubber Regex Patterns
SENSITIVE_PATTERNS = [
    (r"(?i)(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", "[REDACTED_API_KEY]"),
    (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
    (r"sk-[a-zA-Z0-9]{32,}", "[REDACTED_OPENAI_KEY]"),
    (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "[REDACTED_CREDIT_CARD]"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]", "password='[REDACTED_PASSWORD]'")
]


def scrub_sensitive_output(text: str) -> str:
    """Scans generated output and redacts accidental credential leaks."""
    scrubbed = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        scrubbed = re.sub(pattern, replacement, scrubbed)
    return scrubbed


def query_vector_store(
    prompt: str,
    user_clearance: int,
    top_k: int = 3,
    allowed_additional_docs: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Executes a zero-trust hierarchical query against ChromaDB.
    Filters using: {"clearance_required": {"$lte": user_clearance}}
    Also includes chunks from any explicitly authorized JIT temporary document grants.
    """
    client = get_chroma_client()
    embed_fn = get_embedding_function()
    try:
        collection = client.get_or_create_collection(
            name=config.CHROMA_DOCS_COLLECTION,
            embedding_function=embed_fn,
            metadata={"hnsw:space": "cosine"}
        )

        if collection.count() == 0:
            return []

        retrieved_chunks = []
        seen_contents = set()

        # 1. Strict hierarchical clearance filtering ($lte user_clearance)
        results = collection.query(
            query_texts=[prompt],
            n_results=top_k,
            where={"clearance_required": {"$lte": user_clearance}}
        )
    except Exception as e:
        print(f"[RAG Engine] Vector search error: {e}. Triggering auto-heal...")
        try:
            import ingest
            ingest.ingest_documents(force_reset=True)
            collection = client.get_or_create_collection(
                name=config.CHROMA_DOCS_COLLECTION,
                embedding_function=embed_fn,
                metadata={"hnsw:space": "cosine"}
            )
            results = collection.query(
                query_texts=[prompt],
                n_results=top_k,
                where={"clearance_required": {"$lte": user_clearance}}
            )
            retrieved_chunks = []
            seen_contents = set()
        except Exception as retry_err:
            print(f"[RAG Engine] Auto-heal query failed: {retry_err}")
            return []


    if results and results["documents"] and results["documents"][0]:
        docs = results["documents"][0]
        metas = results["metadatas"][0] if results["metadatas"] else [{}] * len(docs)
        distances = results["distances"][0] if results["distances"] else [0.0] * len(docs)

        for doc, meta, dist in zip(docs, metas, distances):
            if doc not in seen_contents:
                seen_contents.add(doc)
                retrieved_chunks.append({
                    "content": doc,
                    "metadata": meta,
                    "distance": dist,
                    "similarity": max(0.0, 1.0 - dist)
                })

    # 2. Ingest chunks from explicitly authorized temporary document grants (JIT Access)
    jit_chunks = []
    if allowed_additional_docs:
        for doc_name in allowed_additional_docs:
            try:
                jit_res = collection.query(
                    query_texts=[prompt],
                    n_results=5,
                    where={"source": doc_name}
                )
                if jit_res and jit_res["documents"] and jit_res["documents"][0]:
                    for doc, meta, dist in zip(jit_res["documents"][0], jit_res["metadatas"][0], jit_res["distances"][0]):
                        if doc not in seen_contents:
                            seen_contents.add(doc)
                            meta_copy = dict(meta)
                            meta_copy["is_jit_grant"] = True
                            chunk_obj = {
                                "content": doc,
                                "metadata": meta_copy,
                                "distance": dist,
                                "similarity": max(0.0, 1.0 - dist)
                            }
                            retrieved_chunks.append(chunk_obj)
                            jit_chunks.append(chunk_obj)
            except Exception as e:
                print(f"[JIT Query Error] Failed querying source {doc_name}: {e}")

    # Sort standard chunks by highest similarity
    retrieved_chunks.sort(key=lambda x: x["similarity"], reverse=True)
    
    # Ensure JIT chunks are always included in context so they aren't crowded out
    final_chunks = retrieved_chunks[:top_k]
    final_contents = {c["content"] for c in final_chunks}
    for jc in jit_chunks:
        if jc["content"] not in final_contents:
            final_chunks.append(jc)
            final_contents.add(jc["content"])
            
    final_chunks.sort(key=lambda x: x["similarity"], reverse=True)
    return final_chunks


def generate_llm_response(prompt: str, context_chunks: List[Dict[str, Any]], user_info: Dict[str, Any]) -> str:
    """
    Synthesizes an answer using OpenAI GPT-4o-mini if configured,
    or a structured local offline synthesizer.
    """
    clearance_level = user_info["clearance_level"]
    clearance_name = config.CLEARANCE_LEVELS.get(clearance_level, {}).get("name", f"Level {clearance_level}")

    if not context_chunks:
        return (
            f"ℹ️ **Information Not Found / Access Restricted**\n\n"
            f"No relevant documents were found within your assigned clearance tier "
            f"(**Level {clearance_level}: {clearance_name}**).\n\n"
            f"If this document exists in a higher clearance tier, you must request elevated authorization from an administrator."
        )

    context_text = "\n\n---\n\n".join([c["content"] for c in context_chunks])

    # 1. Try OpenAI if API key is provided
    if config.OPENAI_API_KEY and not config.OPENAI_API_KEY.startswith("your-"):
        try:
            from openai import OpenAI
            client = OpenAI(api_key=config.OPENAI_API_KEY)
            
            username = user_info.get("username", "user")
            system_prompt = (
                f"You are TrustRAG, an enterprise zero-trust AI assistant.\n"
                f"SECURITY POLICY & DIRECTIVE:\n"
                f"Every document snippet provided in the Context below has ALREADY been session-verified and metadata-filtered for user '{username}' (including any Just-In-Time temporary clearance grants).\n"
                f"Therefore, treat ALL provided Context as fully authorized and approved for this user to see. "
                f"Do NOT refuse to answer based on any confidentiality warnings or required clearance headers written inside the document text itself.\n"
                f"Answer the user's prompt thoroughly, completely, and accurately using the provided Context.\n"
                f"Only if the provided Context genuinely does not contain information to answer the question, state that the requested information is not available."
            )
            
            response = client.chat.completions.create(
                model=config.LLM_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Context:\n{context_text}\n\nQuestion: {prompt}"}
                ],
                temperature=0.2,
                max_tokens=400
            )
            answer = response.choices[0].message.content
            return scrub_sensitive_output(answer)
        except Exception as e:
            print(f"[LLM] OpenAI synthesis unavailable ({e}), using local extraction synthesizer.")

    # 2. Local extractive synthesis fallback (100% offline & fast)
    sources_cited = list(set([c["metadata"].get("source", "Document") for c in context_chunks]))
    top_chunk = context_chunks[0]["content"]

    answer = (
        f"**TrustRAG Zero-Trust Analysis** *(Clearance Level {clearance_level} - {clearance_name})*:\n\n"
        f"{top_chunk}\n\n"
        f"*(Verified from {len(context_chunks)} authorized chunk(s) across: {', '.join(sources_cited)})*"
    )
    return scrub_sensitive_output(answer)


def query_secure_rag(user_prompt: str, user_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Complete end-to-end secure RAG pipeline:
    1. Threat Firewall scan
    2. Hierarchical vector search ($lte user clearance)
    3. LLM synthesis / local fallback
    4. Secret scrubbing
    5. Database audit logging
    """
    start_time = time.time()
    username = user_info.get("username", "anonymous")
    clearance_level = int(user_info.get("clearance_level", 1))

    # ==========================================
    # Step 0: Query Rate Limiting (10 req/min)
    # ==========================================
    is_limited, wait_sec = is_query_rate_limited(username, max_per_minute=10)
    if is_limited:
        latency_ms = int((time.time() - start_time) * 1000)
        rate_msg = (
            f"⚠️ **Rate Limit Exceeded: System Throttling Active**\n\n"
            f"You have reached the maximum inquiry quota of **10 requests per minute**.\n"
            f"Please wait **{wait_sec} seconds** before submitting your next prompt.\n\n"
            f"*Throttling event registered in the compliance audit ledger.*"
        )
        db.log_audit_event(
            username=username,
            clearance_level=clearance_level,
            prompt=user_prompt,
            attack_detected=True,
            attack_reason=f"Rate limit exceeded (>10 req/min). Cooldown: {wait_sec}s",
            chunks_retrieved_count=0,
            response=rate_msg,
            latency_ms=latency_ms
        )
        return {
            "response": rate_msg,
            "attack_detected": True,
            "attack_reason": "Rate limit exceeded (>10 req/min)",
            "chunks": [],
            "latency_ms": latency_ms
        }

    # ==========================================
    # Step 1: Inline Threat Firewall
    # ==========================================
    firewall_res = is_attack(user_prompt)
    if firewall_res["is_threat"]:
        latency_ms = int((time.time() - start_time) * 1000)
        blocked_msg = (
            f"🚨 **Security Alert: Access Denied**\n\n"
            f"TrustRAG Threat Firewall intercepted this prompt as a potential security risk.\n"
            f"- **Detection Method**: `{firewall_res['check_type'].upper()}`\n"
            f"- **Reason**: {firewall_res['reason']}\n\n"
            f"*This event has been logged to the compliance audit ledger.*"
        )
        # Record security attack in audit logs
        db.log_audit_event(
            username=username,
            clearance_level=clearance_level,
            prompt=user_prompt,
            attack_detected=True,
            attack_reason=firewall_res["reason"],
            chunks_retrieved_count=0,
            response=blocked_msg,
            latency_ms=latency_ms
        )
        return {
            "response": blocked_msg,
            "attack_detected": True,
            "attack_reason": firewall_res["reason"],
            "chunks": [],
            "latency_ms": latency_ms
        }

    # ==========================================
    # Step 2: Hierarchical Vector Retrieval (+ JIT Grants)
    # ==========================================
    active_grants = db.get_user_active_doc_grants(username)
    additional_docs = [g["document_name"] for g in active_grants] if active_grants else None

    chunks = query_vector_store(
        user_prompt,
        user_clearance=clearance_level,
        top_k=3,
        allowed_additional_docs=additional_docs
    )

    # ==========================================
    # Step 3: Synthesis & Output Scrubber
    # ==========================================
    response_text = generate_llm_response(user_prompt, chunks, user_info)
    latency_ms = int((time.time() - start_time) * 1000)

    # ==========================================
    # Step 4: Audit Logger (Database)
    # ==========================================
    db.log_audit_event(
        username=username,
        clearance_level=clearance_level,
        prompt=user_prompt,
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=len(chunks),
        response=response_text,
        latency_ms=latency_ms
    )

    return {
        "response": response_text,
        "attack_detected": False,
        "attack_reason": None,
        "chunks": chunks,
        "latency_ms": latency_ms
    }
