"""
TrustRAG - Automated Verification Test for JIT Clearance Retrieval
Tests that Just-In-Time document authorization works end-to-end through
the real secure RAG pipeline (vector store querying, threat firewall, and clearance bounds)
WITHOUT bypassing vector search.
"""

import config
import db
import auth
import rag_engine


def test_jit_secure_rag():
    print("=== TrustRAG End-to-End JIT Verification Test ===")
    
    # Authenticate Bob
    bob = auth.authenticate_user("intern_bob", "Password@123")
    assert bob is not None, "Failed to authenticate intern_bob"
    print(f"[1] Authenticated: {bob['username']} (Level {bob['clearance_level']})")

    # Verify active grants exist in DB
    active_grants = db.get_user_active_doc_grants("intern_bob")
    doc_names = [g["document_name"] for g in active_grants]
    print(f"[2] Active JIT Grants: {doc_names}")

    # Query through full RAG engine pipeline (NO raw file reading)
    prompt = "tell me about the payroll"
    print(f"[3] Executing secure RAG query: '{prompt}'...")
    result = rag_engine.query_secure_rag(prompt, bob)

    print("\n--- Pipeline Diagnostic Results ---")
    print(f"Firewall Attack Detected: {result['attack_detected']}")
    print(f"Chunks Retrieved: {len(result['chunks'])}")
    for i, c in enumerate(result["chunks"]):
        src = c["metadata"].get("source", "Unknown")
        is_jit = c["metadata"].get("is_jit_grant", False)
        print(f"  Chunk {i+1}: source='{src}' | is_jit={is_jit} | similarity={c['similarity']:.2%}")

    print("\n--- Secure LLM Response ---")
    print(result["response"])

    assert not result["attack_detected"], "Legitimate prompt was falsely flagged as attack"
    assert len(result["chunks"]) > 0, "No chunks retrieved through secure pipeline"
    assert "salary" in result["response"].lower() or "50,000" in result["response"], "Salary details missing from response"
    print("\n[SUCCESS] End-to-End JIT Pipeline Verification Passed!")


if __name__ == "__main__":
    test_jit_secure_rag()
