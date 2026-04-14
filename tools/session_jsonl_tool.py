#!/usr/bin/env python3
"""
Session JSONL Search - Deep search across past conversations

Search past conversation transcripts stored in JSONL format.
Uses BM25-style keyword matching + snippet extraction for efficient
search without loading full transcripts into context.

Based on the karpathy/autoagent pattern: sessions stored as JSONL,
searched on-demand rather than loaded all at once.
"""

import json
import os
import re
import glob
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from hermes_constants import get_hermes_home


def _get_session_files(hermes_home: str) -> List[str]:
    """Get all JSONL session files."""
    session_dir = Path(hermes_home) / "sessions"
    if not session_dir.exists():
        return []

    # Find all JSONL files in sessions directory
    patterns = [
        session_dir / "*.jsonl",
        session_dir / "**" / "*.jsonl",
    ]

    files = []
    for pattern in patterns:
        files.extend(glob.glob(str(pattern), recursive=True))

    return sorted(files, key=os.path.getmtime, reverse=True)


def _extract_snippets(text: str, query: str, max_length: int = 200) -> List[str]:
    """Extract relevant snippets around query matches."""
    query_words = query.lower().split()
    snippets = []

    text_lower = text.lower()
    for word in query_words:
        idx = text_lower.find(word)
        if idx == -1:
            continue

        # Get context around match
        start = max(0, idx - 50)
        end = min(len(text), idx + max_length)
        snippet = text[start:end].strip()

        # Clean up snippet
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."

        snippets.append(snippet)

    return snippets[:5]  # Max 5 snippets


def session_jsonl_search(
    query: str,
    max_sessions: int = 5,
    max_results_per_session: int = 3,
    date_filter: Optional[str] = None,
    task_id: Optional[str] = None,
) -> str:
    """
    Search past session transcripts for relevant information.

    Uses keyword matching to find sessions matching the query,
    then extracts relevant snippets without loading full transcripts.

    Args:
        query: What to search for
        max_sessions: Maximum sessions to search (default 5)
        max_results_per_session: Max matches per session (default 3)
        date_filter: Optional date filter (e.g., "2026-04", "last-week")

    Returns:
        JSON with matching sessions and snippets
    """
    if not query or not query.strip():
        return json.dumps({"error": "Query is required"}, ensure_ascii=False)

    query = query.strip()
    hermes_home = str(get_hermes_home())
    session_files = _get_session_files(hermes_home)

    if not session_files:
        return json.dumps(
            {"query": query, "results": [], "message": "No session files found"},
            ensure_ascii=False,
        )

    # Filter by date if specified
    if date_filter:
        filtered = []
        for f in session_files:
            mtime = datetime.fromtimestamp(os.path.getmtime(f))
            if date_filter == "last-week":
                from datetime import timedelta

                week_ago = datetime.now() - timedelta(days=7)
                if mtime >= week_ago:
                    filtered.append(f)
            elif "-" in date_filter:  # Month like "2026-04"
                if mtime.strftime("%Y-%m") == date_filter:
                    filtered.append(f)
            else:
                filtered.append(f)
        session_files = filtered[:max_sessions]
    else:
        session_files = session_files[:max_sessions]

    results = []

    for session_file in session_files:
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Quick keyword check
            content_lower = content.lower()
            query_lower = query.lower()

            if query_lower not in content_lower:
                continue

            # Extract snippets
            snippets = _extract_snippets(content, query)

            if snippets:
                # Get session metadata
                session_name = Path(session_file).stem
                mtime = datetime.fromtimestamp(os.path.getmtime(session_file))

                results.append(
                    {
                        "session": session_name,
                        "file": str(session_file),
                        "date": mtime.isoformat(),
                        "snippets": snippets[:max_results_per_session],
                        "match_count": content_lower.count(query_lower),
                    }
                )

        except Exception as e:
            continue

    if not results:
        return json.dumps(
            {"query": query, "results": [], "message": "No matching sessions found"},
            ensure_ascii=False,
        )

    return json.dumps(
        {
            "query": query,
            "results": results,
            "sessions_searched": len(session_files),
            "matches_found": len(results),
        },
        ensure_ascii=False,
    )


def session_jsonl_list(
    limit: int = 10,
    task_id: Optional[str] = None,
) -> str:
    """
    List recent session files.

    Args:
        limit: Maximum sessions to list (default 10)

    Returns:
        JSON list of recent sessions
    """
    hermes_home = str(get_hermes_home())
    session_files = _get_session_files(hermes_home)[:limit]

    sessions = []
    for f in session_files:
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(f))
            size = os.path.getsize(f)

            sessions.append(
                {
                    "name": Path(f).stem,
                    "file": str(f),
                    "date": mtime.isoformat(),
                    "size_bytes": size,
                }
            )
        except Exception:
            continue

    return json.dumps(
        {"sessions": sessions, "count": len(sessions)}, ensure_ascii=False
    )


def session_jsonl_context(
    session_name: str,
    max_turns: int = 10,
    task_id: Optional[str] = None,
) -> str:
    """
    Load specific session turns as context (for deep recall).

    Use this when you need detailed context from a specific past session.
    Unlike search which returns snippets, this loads full turns.

    Args:
        session_name: Name of session to load
        max_turns: Maximum turns to load (default 10)

    Returns:
        JSON with session turns
    """
    hermes_home = str(get_hermes_home())
    session_path = Path(hermes_home) / "sessions" / f"{session_name}.jsonl"

    if not session_path.exists():
        return json.dumps(
            {"error": f"Session not found: {session_name}"}, ensure_ascii=False
        )

    try:
        with open(session_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Parse JSONL lines
        turns = []
        for line in lines[-max_turns:]:
            try:
                turn = json.loads(line)
                turns.append(turn)
            except json.JSONDecodeError:
                continue

        return json.dumps(
            {"session": session_name, "turns": turns, "count": len(turns)},
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Failed to load session: {e}"}, ensure_ascii=False)


SESSION_SEARCH_SCHEMA = {
    "name": "session_search_deep",
    "description": (
        "Search past conversation transcripts stored as JSONL. "
        "Uses keyword matching to find relevant sessions, extracts snippets "
        "without loading full transcripts.\n\n"
        "Use this when:\n"
        "- You need to recall something from past sessions\n"
        "- User references a previous conversation\n"
        "- You want context from a specific past session\n\n"
        "Unlike session_search tool, this searches raw JSONL files for deeper recall."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to search for"},
            "max_sessions": {
                "type": "integer",
                "description": "Max sessions to search (default 5)",
                "default": 5,
            },
            "max_results_per_session": {
                "type": "integer",
                "description": "Max matches per session (default 3)",
                "default": 3,
            },
            "date_filter": {
                "type": "string",
                "description": "Optional: 'last-week', '2026-04'",
            },
        },
        "required": ["query"],
    },
}

SESSION_LIST_SCHEMA = {
    "name": "session_list",
    "description": "List recent session files - useful to see what conversations are stored.",
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Max sessions to list (default 10)",
                "default": 10,
            },
        },
    },
}

SESSION_CONTEXT_SCHEMA = {
    "name": "session_load_context",
    "description": (
        "Load specific session turns as context. Use for deep recall when you need "
        "full conversation details from a specific past session."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "session_name": {
                "type": "string",
                "description": "Name of session to load",
            },
            "max_turns": {
                "type": "integer",
                "description": "Max turns to load (default 10)",
                "default": 10,
            },
        },
        "required": ["session_name"],
    },
}


from tools.registry import registry

registry.register(
    name="session_search_deep",
    toolset="session-jsonl",
    schema=SESSION_SEARCH_SCHEMA,
    handler=lambda args, **kw: session_jsonl_search(
        query=args.get("query", ""),
        max_sessions=args.get("max_sessions", 5),
        max_results_per_session=args.get("max_results_per_session", 3),
        date_filter=args.get("date_filter"),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Deep search past session JSONL files",
    emoji="🔍",
)

registry.register(
    name="session_list",
    toolset="session-jsonl",
    schema=SESSION_LIST_SCHEMA,
    handler=lambda args, **kw: session_jsonl_list(
        limit=args.get("limit", 10),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="List recent session files",
    emoji="📋",
)

registry.register(
    name="session_load_context",
    toolset="session-jsonl",
    schema=SESSION_CONTEXT_SCHEMA,
    handler=lambda args, **kw: session_jsonl_context(
        session_name=args.get("session_name", ""),
        max_turns=args.get("max_turns", 10),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Load specific session as context",
    emoji="📜",
)
