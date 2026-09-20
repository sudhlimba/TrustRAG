"""
TrustRAG Action-Gated Conversational Copilot (ChatOps Engine)
Enables conversational administration, automated JIT grants, kill-switch revocation,
audit verification, and user management directly from the Secure Knowledge Assistant.

Strictly gated by Python-enforced Zero-Trust RBAC (Clearance Levels 1-4) with
cryptographic audit anchoring and interactive two-step confirmation for destructive tasks.
"""

import re
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List

import config
import db


# ==============================================================================
# Document Catalog & Resolution
# ==============================================================================

def get_all_enterprise_documents() -> List[Dict[str, Any]]:
    """Returns a list of all indexed enterprise files across all clearance tiers."""
    docs = []
    for lvl, info in config.CLEARANCE_LEVELS.items():
        d_dir = Path(info["allowed_data_dir"])
        if d_dir.exists():
            for f in sorted(d_dir.glob("*.*")):
                docs.append({
                    "filename": f.name,
                    "stem": f.stem,
                    "level": lvl,
                    "level_name": info["name"],
                    "path": str(f)
                })
    return docs


def resolve_document_by_keyword(query: str) -> Optional[Tuple[str, int]]:
    """
    Fuzzy resolves a user prompt document reference to a concrete enterprise file.
    Returns (filename, required_clearance) or None.
    """
    clean_query = query.strip().lower()
    docs = get_all_enterprise_documents()

    # 1. Exact match on filename or stem
    for d in docs:
        if clean_query == d["filename"].lower() or clean_query == d["stem"].lower():
            return d["filename"], d["level"]

    # 2. Filename substring match
    for d in docs:
        if d["filename"].lower() in clean_query or clean_query in d["filename"].lower():
            return d["filename"], d["level"]

    # 3. Stem keyword match
    keywords = [k for k in re.split(r"[\s_]+", clean_query) if len(k) > 3]
    for d in docs:
        stem_lower = d["stem"].lower()
        if any(kw in stem_lower for kw in keywords):
            return d["filename"], d["level"]

    return None


# ==============================================================================
# Action Intent Parsing & Clearance Gating
# ==============================================================================

def _detect_action_intent(prompt: str, user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Inspects user prompt for conversational commands and validates RBAC clearance.
    Returns None if prompt is a standard knowledge query.
    Returns an action descriptor dict if an administrative or self-service intent is detected.
    """
    raw = prompt.strip()
    p_lower = raw.lower()
    user_name = user.get("username", "anonymous")
    user_level = int(user.get("clearance_level", 1))

    # -------------------------------------------------------------
    # Action: Help / Available Commands
    # -------------------------------------------------------------
    if re.search(r"\b(what can you do|what commands|list commands|help copilot|chatops help|available actions)\b", p_lower):
        return {
            "action_id": "show_help",
            "required_clearance": 1,
            "authorized": True,
            "requires_confirmation": False,
            "params": {},
            "description": "Show available ChatOps commands for your clearance level"
        }

    # -------------------------------------------------------------
    # Action: Delete / Offboard User (Level 4 Exec Only)
    # -------------------------------------------------------------
    del_match = re.search(
        r"\b(?:remove|delete|offboard|purge|terminate account)\s+(?:user\s+)?([a-zA-Z0-9_\-\.]+)",
        p_lower
    )
    if del_match:
        target_user = del_match.group(1).strip()
        # If a pronoun or generic word was matched, look for the actual subject mentioned in the prompt
        if target_user in ["him", "her", "them", "it", "user", "account", "someone", "person", "the", "this"]:
            # Check if any registered user is mentioned in the prompt
            try:
                all_u = [u["username"].lower() for u in db.get_all_users()]
                found_u = next((u for u in all_u if u in p_lower), None)
                if found_u:
                    target_user = found_u
                else:
                    # Look for candidate name pattern like "[name] is not a part" or similar subject
                    subj_match = re.search(r"\b([a-zA-Z0-9_\-\.]+)\s+is\s+(?:not\s+)?(?:a\s+)?(?:part|an\s+employee|in|with|working)\b", p_lower)
                    if subj_match:
                        target_user = subj_match.group(1).strip()
            except Exception:
                pass

        # Avoid matching words like "access", "notifications", "cache" as usernames
        if target_user not in ["access", "notifications", "all", "the", "my", "clearance", "chat", "him", "her", "them"]:
            req_lvl = 4
            authorized = user_level >= req_lvl
            return {
                "action_id": "delete_user",
                "required_clearance": req_lvl,
                "authorized": authorized,
                "requires_confirmation": True,
                "params": {"target_username": target_user},
                "description": f"Permanently offboard user **'{target_user}'** and purge all active sessions and grants",
                "confirmation_prompt": f"Are you sure you want to permanently delete user account **'{target_user}'** from the enterprise directory?"
            }


    # -------------------------------------------------------------
    # Action: Update Clearance / Promote Demote User (Level 4 Exec Only)
    # -------------------------------------------------------------
    clearance_match = re.search(
        r"\b(?:set|change|update|promote|demote)\s+(?:user\s+)?([a-zA-Z0-9_\-\.]+)\s+(?:clearance|level|tier)\s+(?:to\s+)?(?:level\s+)?([1-4])",
        p_lower
    )
    if not clearance_match:
        clearance_match = re.search(
            r"\b(?:promote|demote)\s+(?:user\s+)?([a-zA-Z0-9_\-\.]+)\s+to\s+(?:level\s+)?([1-4])",
            p_lower
        )
    if clearance_match:
        target_user = clearance_match.group(1).strip()
        new_lvl = int(clearance_match.group(2))
        req_lvl = 4
        authorized = user_level >= req_lvl
        lvl_name = config.CLEARANCE_LEVELS.get(new_lvl, {}).get("name", f"Level {new_lvl}")
        return {
            "action_id": "update_clearance",
            "required_clearance": req_lvl,
            "authorized": authorized,
            "requires_confirmation": True,
            "params": {"target_username": target_user, "new_level": new_lvl},
            "description": f"Adjust clearance of user **'{target_user}'** to **Level {new_lvl} ({lvl_name})**",
            "confirmation_prompt": f"Confirm setting **'{target_user}'** security clearance to **Level {new_lvl} ({lvl_name})**?"
        }

    # -------------------------------------------------------------
    # Action: Direct Grant Document Access (Level 3+ Authority)
    # -------------------------------------------------------------
    grant_match = re.search(
        r"\b(?:grant|give|allow)\s+(?:user\s+)?([a-zA-Z0-9_\-\.]+)\s+(?:access\s+to\s+|to\s+read\s+)(.+?)(?:\s+for\s+(\d+)\s*h(?:our)?s?)?$",
        p_lower
    )
    if grant_match:
        target_user = grant_match.group(1).strip()
        doc_query = grant_match.group(2).strip()
        duration_hours = int(grant_match.group(3)) if grant_match.group(3) else 4

        res = resolve_document_by_keyword(doc_query)
        resolved_doc, doc_level = res if res else (doc_query, 3)

        req_lvl = max(3, doc_level)
        authorized = user_level >= req_lvl
        return {
            "action_id": "grant_doc_access",
            "required_clearance": req_lvl,
            "authorized": authorized,
            "requires_confirmation": True,
            "params": {
                "target_username": target_user,
                "document_name": resolved_doc,
                "document_clearance": doc_level,
                "duration_hours": duration_hours
            },
            "description": f"Grant user **'{target_user}'** {duration_hours}h JIT access to **'{resolved_doc}'** (Level {doc_level})",
            "confirmation_prompt": f"Confirm granting **'{target_user}'** temporary access to **'{resolved_doc}'** for **{duration_hours} hour(s)**?"
        }

    # -------------------------------------------------------------
    # Action: Revoke Document Access Kill Switch (Level 3+ Authority)
    # -------------------------------------------------------------
    # Case A: "revoke access to <doc> from/for <user>"
    rev_a = re.search(r"\b(?:revoke|terminate|kill)\s+(?:access\s+to\s+)(.+?)\s+(?:from|for)\s+([a-zA-Z0-9_\-\.]+)", p_lower)
    # Case B: "revoke <user> access to <doc>" or "revoke access for <user> to <doc>"
    rev_b = re.search(r"\b(?:revoke|terminate|kill)\s+(?:access\s+(?:for|from)\s+)?([a-zA-Z0-9_\-\.]+)\s+(?:access\s+to\s+|to\s+)(.+)", p_lower)

    target_user, doc_query = None, None
    if rev_a:
        doc_query = rev_a.group(1).strip()
        target_user = rev_a.group(2).strip()
    elif rev_b:
        target_user = rev_b.group(1).strip()
        doc_query = rev_b.group(2).strip()

    if target_user and doc_query and target_user not in ["all", "the", "my", "notifications", "user", "access"]:
        res = resolve_document_by_keyword(doc_query)
        resolved_doc = res[0] if res else doc_query
        doc_lvl = res[1] if res else 3
        req_lvl = max(3, doc_lvl)
        authorized = user_level >= req_lvl
        return {
            "action_id": "revoke_doc_access",
            "required_clearance": req_lvl,
            "authorized": authorized,
            "requires_confirmation": True,
            "params": {
                "target_username": target_user,
                "document_name": resolved_doc
            },
            "description": f"Emergency Kill Switch: Revoke active JIT access to **'{resolved_doc}'** from **'{target_user}'**",
            "confirmation_prompt": f"Confirm emergency revocation of **'{target_user}'** access to **'{resolved_doc}'**?"
        }

    # -------------------------------------------------------------
    # Action: Verify Cryptographic Audit Integrity (Level 2+)
    # -------------------------------------------------------------
    if re.search(r"\b(verify|check)\s+(?:the\s+)?(?:audit\s+)?(?:log|ledger|chain|blockchain|integrity)\b", p_lower):
        req_lvl = 2
        authorized = user_level >= req_lvl
        return {
            "action_id": "verify_audit",
            "required_clearance": req_lvl,
            "authorized": authorized,
            "requires_confirmation": False,
            "params": {},
            "description": "Cryptographically traverse and verify the SHA-256 audit ledger hash chain"
        }

    # -------------------------------------------------------------
    # Action: Audit Telemetry / Attack Stats (Level 2+)
    # -------------------------------------------------------------
    if re.search(r"\b(audit\s+telemetry|attack\s+stats|firewall\s+stats|how\s+many\s+attacks|audit\s+summary|security\s+stats)\b", p_lower):
        req_lvl = 2
        authorized = user_level >= req_lvl
        return {
            "action_id": "audit_telemetry",
            "required_clearance": req_lvl,
            "authorized": authorized,
            "requires_confirmation": False,
            "params": {},
            "description": "Fetch real-time Threat Firewall metrics and audit event tallies"
        }

    # -------------------------------------------------------------
    # Action: List Enterprise Users / Directory (Level 2+)
    # -------------------------------------------------------------
    if re.search(r"\b(?:list|show|view|display)\s+(?:the\s+)?(?:(?:active|enterprise)\s+)*(?:users|accounts|directory|employees)\b", p_lower):
        req_lvl = 2
        authorized = user_level >= req_lvl
        return {
            "action_id": "list_users",
            "required_clearance": req_lvl,
            "authorized": authorized,
            "requires_confirmation": False,
            "params": {},
            "description": "Display enterprise directory with clearance levels and roles"
        }

    # -------------------------------------------------------------
    # Action: List Active JIT Grants (Level 1 for self, Level 3+ for all)
    # -------------------------------------------------------------
    if re.search(r"\b(list\s+active\s+grants|show\s+active\s+grants|unlocked\s+files|active\s+permissions|my\s+active\s+access)\b", p_lower):
        return {
            "action_id": "list_grants",
            "required_clearance": 1,
            "authorized": True,
            "requires_confirmation": False,
            "params": {},
            "description": "List currently valid Just-In-Time document access grants"
        }

    # -------------------------------------------------------------
    # Action: Check Inbox / Notifications (Level 1 Self-Service)
    # -------------------------------------------------------------
    if re.search(r"\b(check\s+(?:my\s+)?inbox|show\s+(?:my\s+)?notifications|view\s+(?:my\s+)?alerts|my\s+inbox|unread\s+notifications)\b", p_lower):
        return {
            "action_id": "check_inbox",
            "required_clearance": 1,
            "authorized": True,
            "requires_confirmation": False,
            "params": {},
            "description": "Fetch personal inbox tickets and security notifications"
        }

    # -------------------------------------------------------------
    # Action: Mark Notifications as Read (Level 1 Self-Service)
    # -------------------------------------------------------------
    if re.search(r"\b(mark\s+(?:all\s+)?notifications\s+(?:as\s+)?read|clear\s+(?:my\s+)?notifications|mark\s+inbox\s+(?:as\s+)?read)\b", p_lower):
        return {
            "action_id": "mark_read",
            "required_clearance": 1,
            "authorized": True,
            "requires_confirmation": False,
            "params": {},
            "description": "Mark all inbox notifications as read"
        }

    # -------------------------------------------------------------
    # Action: Self-Service Request Document Access (Level 1)
    # -------------------------------------------------------------
    req_doc_match = re.search(
        r"\b(?:request|apply\s+for)\s+(?:access\s+to|clearance\s+for)\s+(.+?)(?:\s+for\s+(\d+)\s*h(?:our)?s?)?$",
        p_lower
    )
    if req_doc_match:
        doc_query = req_doc_match.group(1).strip()
        hours = int(req_doc_match.group(2)) if req_doc_match.group(2) else 4
        res = resolve_document_by_keyword(doc_query)
        if res:
            resolved_doc, doc_lvl = res
            return {
                "action_id": "request_doc_access",
                "required_clearance": 1,
                "authorized": True,
                "requires_confirmation": False,
                "params": {
                    "document_name": resolved_doc,
                    "document_clearance": doc_lvl,
                    "duration_hours": hours,
                    "justification": f"Requested via Secure Knowledge Assistant chat session by {user_name}"
                },
                "description": f"Submit JIT access request for **'{resolved_doc}'** (Level {doc_lvl})"
            }

    # -------------------------------------------------------------
    # Action: Self-Service Request Clearance Promotion (Level 1)
    # -------------------------------------------------------------
    req_prom_match = re.search(
        r"\b(?:request|apply\s+for)\s+(?:clearance\s+escalation|promotion|upgrade)\s+(?:to\s+)?(?:level\s+)?([1-4])",
        p_lower
    )
    if req_prom_match:
        req_lvl = int(req_prom_match.group(1))
        return {
            "action_id": "request_promotion",
            "required_clearance": 1,
            "authorized": True,
            "requires_confirmation": False,
            "params": {
                "requested_clearance": req_lvl,
                "justification": f"Clearance promotion application submitted via conversational assistant by {user_name}"
            },
            "description": f"Submit permanent clearance escalation application to Level {req_lvl}"
        }

    # No administrative action detected; treat as knowledge query
    return None


def parse_chat_action(prompt: str, user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Public entry point for chat action evaluation.
    Inspects user prompt for conversational commands, checks RBAC permissions,
    and logs access denial audit events if user clearance is insufficient.
    """
    action = _detect_action_intent(prompt, user)
    if not action:
        return None

    user_name = user.get("username", "anonymous")
    user_level = int(user.get("clearance_level", 1))

    if not action.get("authorized", False):
        req_lvl = action["required_clearance"]
        req_name = config.CLEARANCE_LEVELS.get(req_lvl, {}).get("name", f"Level {req_lvl}")
        user_name_lvl = config.CLEARANCE_LEVELS.get(user_level, {}).get("name", f"Level {user_level}")

        action["denial_response"] = (
            f"🛑 **Permission Denied: Insufficient Security Clearance**\n\n"
            f"The requested operation (`{action['action_id']}`) requires **Clearance Level {req_lvl} ({req_name})** authorization.\n"
            f"Your current authenticated session holds **Clearance Level {user_level} ({user_name_lvl})**.\n\n"
            f"*Security violation logged into the cryptographic audit ledger.*"
        )
        # Record security audit event
        try:
            db.log_audit_event(
                username=user_name,
                clearance_level=user_level,
                prompt=f"[ChatOps Violation] Unauthorized attempt to invoke '{action['action_id']}': {prompt}",
                attack_detected=True,
                attack_reason=f"Insufficient Clearance: Required Level {req_lvl}, Held Level {user_level}",
                chunks_retrieved_count=0,
                response=action["denial_response"],
                latency_ms=0
            )
        except Exception as e:
            print(f"[Audit Log Error] Failed logging action violation: {e}")

    return action


# ==============================================================================
# Action Execution Handler
# ==============================================================================

def execute_chat_action(action_data: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes an action, creates appropriate audit trails, and returns a formatted response.
    """
    action_id = action_data["action_id"]
    params = action_data.get("params", {})
    user_name = user["username"]
    user_level = user["clearance_level"]

    # 1. Show Help
    if action_id == "show_help":
        tier_help = []
        tier_help.append("### 🤖 TrustRAG Conversational Copilot Capabilities\n")
        tier_help.append(f"Authenticated as: **{user_name}** | Clearance: **Level {user_level} ({config.CLEARANCE_LEVELS[user_level]['name']})**\n")
        tier_help.append("You can issue natural language commands directly into the chat box:")

        tier_help.append("\n**🔓 Level 1+ (Self-Service & Inquiry):**")
        tier_help.append("- `check my inbox` — View alerts and grant notifications")
        tier_help.append("- `mark notifications as read` — Acknowledge unread tickets")
        tier_help.append("- `list active grants` — Show currently unlocked documents")
        tier_help.append("- `request access to <document>` — Submit a JIT clearance request")
        tier_help.append("- `request promotion to level <N>` — Apply for permanent clearance escalation")

        if user_level >= 2:
            tier_help.append("\n**🛡️ Level 2+ (Engineering & Audit):**")
            tier_help.append("- `verify audit integrity` — Traverse and validate SHA-256 hash chain")
            tier_help.append("- `audit telemetry` — View firewall interception metrics")
            tier_help.append("- `list users` — View enterprise active directory catalog")

        if user_level >= 3:
            tier_help.append("\n**🔑 Level 3+ (Clearance Authorities):**")
            tier_help.append("- `grant <user> access to <document> for <hours>h` — Direct JIT approval")
            tier_help.append("- `revoke access to <document> for <user>` — Immediate kill switch")

        if user_level >= 4:
            tier_help.append("\n**👑 Level 4 (Executive Governance):**")
            tier_help.append("- `remove user <username>` — Offboard user and purge credentials")
            tier_help.append("- `set <username> clearance to <1-4>` — Instant clearance adjustment")

        return {
            "success": True,
            "response": "\n".join(tier_help),
            "status": "COMMANDS_DISPLAYED"
        }

    # 2. Delete User
    elif action_id == "delete_user":
        target = params["target_username"]
        ok, msg = db.delete_user(target, reviewer_username=user_name)
        if ok:
            resp = (
                f"🗑️ **User Offboarded Successfully**\n\n"
                f"Account **'{target}'** has been purged from the active enterprise directory.\n"
                f"- All pending JIT requests and active document grants terminated.\n"
                f"- Cryptographic audit event logged to tamper-proof chain.\n"
                f"- Session credentials invalidated."
            )
        else:
            resp = f"❌ **Offboarding Failed**: {msg}"
        return {"success": ok, "response": resp, "status": "USER_OFFBOARDED" if ok else "ERROR"}

    # 3. Update Clearance
    elif action_id == "update_clearance":
        target = params["target_username"]
        new_lvl = params["new_level"]
        ok, msg = db.update_user_clearance(target, new_lvl, reviewer_username=user_name)
        lvl_name = config.CLEARANCE_LEVELS.get(new_lvl, {}).get("name", f"Level {new_lvl}")
        if ok:
            resp = (
                f"🛡️ **Security Clearance Updated**\n\n"
                f"Account **'{target}'** has been updated to **Clearance Level {new_lvl} ({lvl_name})**.\n"
                f"- Cryptographic audit event recorded.\n"
                f"- Direct notification ticket dispatched to user's personal inbox."
            )
        else:
            resp = f"❌ **Clearance Update Failed**: {msg}"
        return {"success": ok, "response": resp, "status": "CLEARANCE_UPDATED" if ok else "ERROR"}

    # 4. Grant Document Access
    elif action_id == "grant_doc_access":
        target = params["target_username"]
        doc = params["document_name"]
        doc_lvl = params["document_clearance"]
        hours = params["duration_hours"]

        ok, msg = db.direct_grant_doc_access(
            username=target,
            document_name=doc,
            document_clearance=doc_lvl,
            duration_hours=hours,
            reviewer_username=user_name,
            reviewer_clearance=user_level
        )
        if ok:
            resp = (
                f"🟢 **JIT Privileged Access Granted**\n\n"
                f"User **'{target}'** has been granted **{hours} hour(s)** of temporary clearance to:\n"
                f"- **Document**: `{doc}` (Clearance Level {doc_lvl})\n"
                f"- **Approving Authority**: `{user_name}` (Level {user_level})\n"
                f"- User inbox notified. Auto-expiration scheduled in the compliance ledger."
            )
        else:
            resp = f"❌ **Access Grant Failed**: {msg}"
        return {"success": ok, "response": resp, "status": "GRANT_APPROVED" if ok else "ERROR"}

    # 5. Revoke Document Access (Kill Switch)
    elif action_id == "revoke_doc_access":
        target = params["target_username"]
        doc = params["document_name"]
        ok, msg = db.revoke_doc_grant_by_user_doc(
            username=target,
            document_name=doc,
            reviewer_username=user_name,
            reviewer_clearance=user_level,
            reason="Conversational Kill Switch triggered by security officer"
        )
        if ok:
            resp = (
                f"🛑 **Emergency Kill Switch Executed**\n\n"
                f"Active JIT grant to **'{doc}'** for user **'{target}'** has been terminated immediately.\n"
                f"- High-priority security audit event written to chain.\n"
                f"- Urgent revocation alert dispatched to user's inbox."
            )
        else:
            resp = f"❌ **Revocation Failed**: {msg}"
        return {"success": ok, "response": resp, "status": "GRANT_REVOKED" if ok else "ERROR"}

    # 6. Verify Cryptographic Audit Integrity
    elif action_id == "verify_audit":
        audit_res = db.verify_audit_log_integrity()
        if audit_res["is_valid"]:
            resp = (
                f"🛡️ **Audit Ledger Integrity Verified (100% Cryptographic Match)**\n\n"
                f"- **Chain Status**: ✅ VALID & UNBROKEN\n"
                f"- **Verified Records**: `{audit_res['verified_count']}` SHA-256 blocks\n"
                f"- **Latest Block Hash**: `{audit_res['latest_hash'][:24]}...`\n"
                f"- **Tampering Checks**: No record mutations, deletions, or insertions detected.\n\n"
                f"*Traversed from Genesis Block: SOC-2 / ISO-27001 Cryptographic Proof Anchor.*"
            )
        else:
            resp = (
                f"🚨 **CRITICAL: CRYPTOGRAPHIC AUDIT LEDGER COMPROMISED**\n\n"
                f"- **Chain Status**: ❌ BROKEN / TAMPERED\n"
                f"- **Tampered Block**: Record #{audit_res.get('tampered_id', 'Unknown')}\n"
                f"- **Detail**: {audit_res.get('error_msg')}\n\n"
                f"*Immediate incident response escalation recommended.*"
            )
        return {"success": audit_res["is_valid"], "response": resp, "status": "AUDIT_VERIFIED"}

    # 7. Audit Telemetry & Threat Metrics
    elif action_id == "audit_telemetry":
        summary = db.get_audit_summary()
        tot = summary["total_queries"]
        atk = summary["attacks_blocked"]
        clean = summary["clean_queries"]
        rate = (atk / tot * 100) if tot > 0 else 0.0

        resp = (
            f"📊 **TrustRAG Security & Threat Telemetry**\n\n"
            f"| Metric | Count | Status |\n"
            f"| :--- | :--- | :--- |\n"
            f"| **Total Inquiries Evaluated** | `{tot}` | 🟢 Active |\n"
            f"| **Clean / Authorized Queries** | `{clean}` | 🛡️ Verified |\n"
            f"| **Firewall Attacks Intercepted** | `{atk}` | 🚨 Blocked |\n"
            f"| **Threat Interception Ratio** | `{rate:.1f}%` | ⚡ Protected |\n\n"
            f"*Real-time metrics anchored against sqlite/postgres audit persistence.*"
        )
        return {"success": True, "response": resp, "status": "TELEMETRY_FETCHED"}

    # 8. List Users / Active Directory
    elif action_id == "list_users":
        all_users = db.get_all_users()
        lines = [
            f"👥 **Enterprise Active Directory ({len(all_users)} Accounts)**\n",
            "| Username | Role | Security Clearance | Created |",
            "| :--- | :--- | :--- | :--- |"
        ]
        for u in all_users:
            lvl = u["clearance_level"]
            lvl_name = config.CLEARANCE_LEVELS.get(lvl, {}).get("name", f"Level {lvl}")
            lines.append(f"| `{u['username']}` | {u['role']} | **Level {lvl}** ({lvl_name}) | {str(u['created_at'])[:10]} |")

        return {"success": True, "response": "\n".join(lines), "status": "USERS_LISTED"}

    # 9. List Active JIT Grants
    elif action_id == "list_grants":
        if user_level >= 3:
            grants = db.get_all_active_doc_grants(reviewer_clearance=user_level)
            header = f"⏱️ **Active Enterprise JIT Grants ({len(grants)})**"
        else:
            grants = db.get_user_active_doc_grants(user_name)
            header = f"⏱️ **Your Active Unlocked Files ({len(grants)})**"

        if not grants:
            resp = f"{header}\n\n*No temporary JIT document grants currently active.*"
        else:
            lines = [
                f"{header}\n",
                "| User | Document | Required Level | Time Remaining | Granted By |",
                "| :--- | :--- | :--- | :--- | :--- |"
            ]
            for g in grants:
                lines.append(f"| `{g['username']}` | `{g['document_name']}` | Level {g['document_clearance']} | **{g.get('time_remaining_str', 'Active')}** | `{g.get('reviewed_by', 'Authority')}` |")
            resp = "\n".join(lines)

        return {"success": True, "response": resp, "status": "GRANTS_LISTED"}

    # 10. Check Inbox / Notifications
    elif action_id == "check_inbox":
        notifs = db.get_user_notifications(user_name, limit=10)
        unread_count = db.get_unread_notification_count(user_name)
        if not notifs:
            resp = f"📫 **Your Personal Inbox is Empty**\n\nNo notifications or security alerts."
        else:
            lines = [f"📬 **Inbox for '{user_name}' ({unread_count} Unread)**\n"]
            for n in notifs[:6]:
                status_icon = "🔵 [UNREAD]" if not n["is_read"] else "⚪ [READ]"
                lines.append(f"**{n['title']}** {status_icon}")
                lines.append(f"*{n['message']}*")
                lines.append(f"<span style='color:#64748b; font-size:0.75rem;'>From: {n['sender_username']} • {str(n['created_at'])[:16]}</span>\n")
            lines.append("*Type `mark notifications as read` to clear unread badges.*")
            resp = "\n".join(lines)
        return {"success": True, "response": resp, "status": "INBOX_CHECKED"}

    # 11. Mark Notifications Read
    elif action_id == "mark_read":
        db.mark_all_notifications_read(user_name)
        return {
            "success": True,
            "response": "✅ **All inbox notifications marked as read.** Your notification counter has been reset.",
            "status": "NOTIFS_MARKED_READ"
        }

    # 12. Request Document Access
    elif action_id == "request_doc_access":
        doc = params["document_name"]
        doc_lvl = params["document_clearance"]
        hours = params["duration_hours"]
        justification = params["justification"]
        ok, msg = db.submit_doc_access_request(
            username=user_name,
            document_name=doc,
            document_clearance=doc_lvl,
            justification=justification,
            duration_hours=hours
        )
        if ok:
            resp = (
                f"📤 **JIT Access Request Submitted**\n\n"
                f"- **Target File**: `{doc}` (Clearance Level {doc_lvl})\n"
                f"- **Requested Window**: `{hours} hour(s)`\n"
                f"- **Status**: `PENDING APPROVAL`\n\n"
                f"A notification ticket has been dispatched to Level {doc_lvl}+ authorities (e.g. hr_elena, exec_david)."
            )
        else:
            resp = f"ℹ️ **Request Status**: {msg}"
        return {"success": ok, "response": resp, "status": "REQUEST_SUBMITTED"}

    # 13. Request Clearance Promotion
    elif action_id == "request_promotion":
        req_lvl = params["requested_clearance"]
        justification = params["justification"]
        ok, msg = db.submit_clearance_escalation(
            username=user_name,
            current_clearance=user_level,
            requested_clearance=req_lvl,
            justification=justification
        )
        lvl_name = config.CLEARANCE_LEVELS.get(req_lvl, {}).get("name", f"Level {req_lvl}")
        if ok:
            resp = (
                f"⭐ **Clearance Escalation Application Submitted**\n\n"
                f"- **Current Clearance**: Level {user_level}\n"
                f"- **Requested Clearance**: **Level {req_lvl} ({lvl_name})**\n"
                f"- **Status**: `PENDING EXECUTIVE SIGN-OFF`\n\n"
                f"Executive Officers have been notified in their governance inbox."
            )
        else:
            resp = f"ℹ️ **Escalation Status**: {msg}"
        return {"success": ok, "response": resp, "status": "PROMOTION_SUBMITTED"}

    return {
        "success": False,
        "response": f"Unknown action ID '{action_id}'.",
        "status": "ERROR"
    }
