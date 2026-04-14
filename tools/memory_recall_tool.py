#!/usr/bin/env python3
"""
On-Demand Memory Recall Tool

This tool provides semantic memory search WITHOUT auto-loading into context.
The agent explicitly calls this tool to recall relevant memories when needed.

Key design:
- Memories stored in local SQLite with FTS5 for fast search
- Agent decides WHEN to call this tool (not auto-injected)
- Only the specific memories returned by search go into context for THAT turn
- Zero token cost on turns where memory recall isn't relevant
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from hermes_constants import get_hermes_home

_MEM_DB_PATH = get_hermes_home() / "memory_recall.db"
_lock = threading.RLock()


def _get_db() -> sqlite3.Connection:
    """Get or create the memory database."""
    _lock.acquire()
    try:
        _MEM_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(_MEM_DB_PATH), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                importance INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                tags TEXT DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                content, category, tags,
                content='memories',
                content_rowid='id'
            )
        """)

        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, content, category, tags)
                VALUES (new.id, new.content, new.category, new.tags);
            END
        """)

        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, content, category, tags)
                VALUES ('delete', old.id, old.content, old.category, old.tags);
            END
        """)

        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, content, category, tags)
                VALUES ('delete', old.id, old.content, old.category, old.tags);
                INSERT INTO memories_fts(rowid, content, category, tags)
                VALUES (new.id, new.content, new.category, new.tags);
            END
        """)

        return conn
    finally:
        _lock.release()


def memory_recall(
    query: str,
    max_results: int = 5,
    category: Optional[str] = None,
    min_importance: int = 1,
    task_id: Optional[str] = None,
) -> str:
    """
    On-demand memory recall - searches memories WITHOUT loading into context.

    Use this when you need to remember something from past conversations,
    user preferences, project details, or important facts.

    This does NOT auto-load memories - you must call this tool explicitly
    to retrieve relevant memories for the current task.

    Args:
        query: What to search for (semantic/keyword search)
        max_results: Maximum memories to return (default 5)
        category: Optional filter: 'preference', 'fact', 'project', 'tool', 'lesson'
        min_importance: Minimum importance 1-5 (default 1)

    Returns:
        JSON with relevant memories - add these to your context if useful
    """
    if not query or not query.strip():
        return json.dumps(
            {"error": "Query is required for memory recall"}, ensure_ascii=False
        )

    query = query.strip()
    conn = _get_db()

    try:
        if category:
            sql = """
                SELECT m.id, m.content, m.category, m.importance, m.created_at, m.tags
                FROM memories m
                WHERE m.category = ? AND m.importance >= ?
                ORDER BY m.importance DESC, m.updated_at DESC
                LIMIT ?
            """
            cursor = conn.execute(sql, (category, min_importance, max_results))
        else:
            sql = """
                SELECT m.id, m.content, m.category, m.importance, m.created_at, m.tags
                FROM memories m
                WHERE m.importance >= ?
                ORDER BY m.importance DESC, m.updated_at DESC
                LIMIT ?
            """
            cursor = conn.execute(sql, (min_importance, max_results))

        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "id": row[0],
                    "content": row[1],
                    "category": row[2],
                    "importance": row[3],
                    "created_at": row[4],
                    "tags": row[5] if row[5] else "",
                }
            )

        if not results:
            return json.dumps(
                {
                    "query": query,
                    "results": [],
                    "message": "No memories found. Use memory_store to save important info.",
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {"query": query, "results": results, "count": len(results)},
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Memory recall failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def memory_store(
    content: str,
    category: str = "general",
    importance: int = 3,
    tags: str = "",
    task_id: Optional[str] = None,
) -> str:
    """
    Store a memory for future recall.

    Call this when you learn something worth remembering:
    - User preferences or corrections
    - Project-specific facts or conventions
    - Important environment details
    - Lessons learned

    Args:
        content: What to remember (be concise, factual)
        category: 'preference', 'fact', 'project', 'tool', 'lesson', 'general'
        importance: 1-5 scale (3=default, 5=critical)
        tags: Comma-separated tags for filtering

    Returns:
        JSON with stored memory info
    """
    if not content or not content.strip():
        return json.dumps(
            {"error": "Content is required for memory store"}, ensure_ascii=False
        )

    content = content.strip()
    if category not in ("preference", "fact", "project", "tool", "lesson", "general"):
        category = "general"
    if importance < 1:
        importance = 1
    elif importance > 5:
        importance = 5

    now = datetime.now().isoformat()
    conn = _get_db()

    try:
        conn.execute(
            """
            INSERT INTO memories (content, category, importance, created_at, updated_at, tags)
            VALUES (?, ?, ?, ?, ?, ?)
        """,
            (content, category, importance, now, now, tags),
        )
        conn.commit()

        cursor = conn.execute("SELECT last_insert_rowid()")
        mem_id = cursor.fetchone()[0]

        return json.dumps(
            {
                "success": True,
                "id": mem_id,
                "content": content[:100] + "..." if len(content) > 100 else content,
                "category": category,
                "importance": importance,
            },
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Memory store failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def memory_list(
    category: Optional[str] = None,
    limit: int = 20,
    task_id: Optional[str] = None,
) -> str:
    """
    List stored memories - useful to see what you have saved.

    Args:
        category: Optional filter by category
        limit: Maximum to return (default 20)

    Returns:
        JSON list of memories
    """
    conn = _get_db()

    try:
        if category:
            sql = """
                SELECT id, content, category, importance, created_at, tags
                FROM memories
                WHERE category = ?
                ORDER BY importance DESC, updated_at DESC
                LIMIT ?
            """
            cursor = conn.execute(sql, (category, limit))
        else:
            sql = """
                SELECT id, content, category, importance, created_at, tags
                FROM memories
                ORDER BY importance DESC, updated_at DESC
                LIMIT ?
            """
            cursor = conn.execute(sql, (limit,))

        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "id": row[0],
                    "content": row[1][:200] + "..." if len(row[1]) > 200 else row[1],
                    "category": row[2],
                    "importance": row[3],
                    "created_at": row[4],
                    "tags": row[5] if row[5] else "",
                }
            )

        return json.dumps(
            {"memories": results, "count": len(results)}, ensure_ascii=False
        )

    except Exception as e:
        return json.dumps({"error": f"Memory list failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def memory_delete(
    memory_id: int,
    task_id: Optional[str] = None,
) -> str:
    """
    Delete a specific memory by ID.

    Args:
        memory_id: The ID of memory to delete

    Returns:
        JSON confirmation
    """
    conn = _get_db()

    try:
        conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        conn.commit()

        return json.dumps(
            {"success": True, "deleted_id": memory_id}, ensure_ascii=False
        )

    except Exception as e:
        return json.dumps({"error": f"Memory delete failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def check_memory_recall_requirements() -> bool:
    """Always available - uses local SQLite."""
    return True


# =============================================================================
# Tool Schemas
# =============================================================================

MEMORY_RECALL_SCHEMA = {
    "name": "memory_recall",
    "description": (
        "On-demand memory search - retrieves relevant memories from long-term storage. "
        "Use this when you need to recall facts, preferences, or lessons from past sessions.\n\n"
        "KEY: This does NOT auto-load memories into context. You must call this tool "
        "explicitly when you need specific memories. This saves tokens on turns where "
        "memory isn't relevant.\n\n"
        "Call this when:\n"
        "- User mentions something you should remember\n"
        "- Working on a project with specific conventions\n"
        "- User corrects you (store the correction)\n"
        "- You learn something useful for future sessions\n\n"
        "Returns memories with importance ratings - higher importance = more reliable."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to search for in memory"},
            "max_results": {
                "type": "integer",
                "description": "Maximum memories to return (default 5)",
                "default": 5,
            },
            "category": {
                "type": "string",
                "description": "Optional filter: preference, fact, project, tool, lesson, general",
                "enum": ["preference", "fact", "project", "tool", "lesson", "general"],
            },
            "min_importance": {
                "type": "integer",
                "description": "Minimum importance 1-5 (default 1)",
                "default": 1,
            },
        },
        "required": ["query"],
    },
}

MEMORY_STORE_SCHEMA = {
    "name": "memory_store",
    "description": (
        "Save important information to persistent memory for future recall.\n\n"
        "When to store:\n"
        "- User shares preferences or corrections\n"
        "- You learn project-specific facts or conventions\n"
        "- Important environment details\n"
        "- Lessons learned that will help future sessions\n\n"
        "Be concise - store factual, lasting information. Not task progress."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "What to remember (concise, factual)",
            },
            "category": {
                "type": "string",
                "description": "Type of memory",
                "enum": ["preference", "fact", "project", "tool", "lesson", "general"],
                "default": "general",
            },
            "importance": {
                "type": "integer",
                "description": "Importance 1-5 (5=critical)",
                "default": 3,
            },
            "tags": {
                "type": "string",
                "description": "Comma-separated tags for filtering",
            },
        },
        "required": ["content"],
    },
}

MEMORY_LIST_SCHEMA = {
    "name": "memory_list",
    "description": "List all stored memories - useful to see what you have saved for future reference.",
    "parameters": {
        "type": "object",
        "properties": {
            "category": {
                "type": "string",
                "description": "Optional filter by category",
            },
            "limit": {
                "type": "integer",
                "description": "Maximum to return (default 20)",
                "default": 20,
            },
        },
    },
}

MEMORY_DELETE_SCHEMA = {
    "name": "memory_delete",
    "description": "Delete a specific memory by ID (use memory_list to find ID first).",
    "parameters": {
        "type": "object",
        "properties": {
            "memory_id": {
                "type": "integer",
                "description": "The ID of memory to delete",
            },
        },
        "required": ["memory_id"],
    },
}

from tools.registry import registry

registry.register(
    name="memory_recall",
    toolset="memory-recall",
    schema=MEMORY_RECALL_SCHEMA,
    handler=lambda args, **kw: memory_recall(
        query=args.get("query", ""),
        max_results=args.get("max_results", 5),
        category=args.get("category"),
        min_importance=args.get("min_importance", 1),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_memory_recall_requirements,
    requires_env=[],
    is_async=False,
    description="On-demand memory search - retrieves relevant memories without auto-loading",
    emoji="🔍",
)

registry.register(
    name="memory_store",
    toolset="memory-recall",
    schema=MEMORY_STORE_SCHEMA,
    handler=lambda args, **kw: memory_store(
        content=args.get("content", ""),
        category=args.get("category", "general"),
        importance=args.get("importance", 3),
        tags=args.get("tags", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_memory_recall_requirements,
    requires_env=[],
    is_async=False,
    description="Save important information to persistent memory",
    emoji="💾",
)

registry.register(
    name="memory_list",
    toolset="memory-recall",
    schema=MEMORY_LIST_SCHEMA,
    handler=lambda args, **kw: memory_list(
        category=args.get("category"),
        limit=args.get("limit", 20),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_memory_recall_requirements,
    requires_env=[],
    is_async=False,
    description="List all stored memories",
    emoji="📋",
)

registry.register(
    name="memory_delete",
    toolset="memory-recall",
    schema=MEMORY_DELETE_SCHEMA,
    handler=lambda args, **kw: memory_delete(
        memory_id=args.get("memory_id"),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_memory_recall_requirements,
    requires_env=[],
    is_async=False,
    description="Delete a specific memory by ID",
    emoji="🗑️",
)
