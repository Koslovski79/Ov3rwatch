#!/usr/bin/env python3
"""
Wiki Memory System - LLM-maintained personal knowledge base

Based on Karpathy's LLM Wiki pattern: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f

The wiki is a persistent, compounding artifact - knowledge compiled once, kept current.
The LLM writes and maintains all wiki pages. The human curates sources and asks questions.

Architecture:
- Raw sources: immutable input documents
- Wiki: LLM-generated markdown files (summaries, entities, concepts)
- Schema: instructions for how the wiki is structured
"""

import json
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from hermes_constants import get_hermes_home

_WIKI_DIR = get_hermes_home() / "wiki"
_lock = threading.RLock()

SCHEMA_DOC = """
# Wiki Schema

## Page Types

### Entity Pages
- Person, project, tool, concept
- Format: [[entity-name]]
- Frontmatter: tags, created, source_count

### Concept Pages  
- Explanations, tutorials, how-tos
- Format: [[concept-name]]

### Source Pages
- Summary of raw source ingestion
- Links to entity and concept pages it mentions

### Index
- Auto-generated catalog of all pages
- One-line summary + link per page

### Log
- Chronological record of wiki activity
- Format: ## [YYYY-MM-DD] action | source

## Conventions
- Use [[wiki-links]] for cross-references
- Frontmatter in YAML for metadata
- Tags as comma-separated in frontmatter
- TL;DR summaries at top of each page
"""


def _get_db() -> sqlite3.Connection:
    """Get or create the wiki database."""
    _lock.acquire()
    try:
        _WIKI_DIR.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(_WIKI_DIR / "wiki.db"), timeout=5)
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL UNIQUE,
                content TEXT NOT NULL,
                page_type TEXT DEFAULT 'general',
                tags TEXT DEFAULT '',
                source_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(
                title, content, tags,
                content='pages',
                content_rowid='id'
            )
        """)

        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS log_fts USING fts5(
                action, details
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT DEFAULT ''
            )
        """)

        return conn
    finally:
        _lock.release()


def _log_action(action: str, details: str = ""):
    """Log an action to the wiki log."""
    conn = _get_db()
    try:
        conn.execute(
            """
            INSERT INTO log (timestamp, action, details) VALUES (?, ?, ?)
        """,
            (datetime.now().isoformat(), action, details),
        )
        conn.commit()
    finally:
        conn.close()


def wiki_ingest(
    source_title: str,
    source_content: str,
    entities: List[str] = None,
    concepts: List[str] = None,
    tags: str = "",
    task_id: Optional[str] = None,
) -> str:
    """
    Ingest a new source into the wiki.

    Creates a source page with summary, extracts/updates entity pages,
    updates index, and logs the ingest.

    Args:
        source_title: Name of the source
        source_content: Raw content or summary to store
        entities: List of entity names to create/update
        concepts: List of concepts to link
        tags: Comma-separated tags

    Returns:
        JSON with ingest results
    """
    if not source_title or not source_content:
        return json.dumps(
            {"error": "source_title and source_content are required"},
            ensure_ascii=False,
        )

    conn = _get_db()

    try:
        now = datetime.now().isoformat()

        conn.execute(
            """
            INSERT OR REPLACE INTO pages (title, content, page_type, tags, source_count, created_at, updated_at)
            VALUES (?, ?, 'source', ?, 1, ?, ?)
        """,
            (source_title, source_content, tags, now, now),
        )

        for entity in entities or []:
            entity_clean = entity.strip()
            if not entity_clean:
                continue
            entity_content = f"Entity: {entity_clean}\n\nMentioned in: {source_title}\n\nTags: {tags}"

            existing = conn.execute(
                "SELECT source_count FROM pages WHERE title = ? AND page_type = 'entity'",
                (entity_clean,),
            ).fetchone()

            new_count = (existing[0] + 1) if existing else 1

            conn.execute(
                """
                INSERT OR REPLACE INTO pages (title, content, page_type, tags, source_count, created_at, updated_at)
                VALUES (?, ?, 'entity', ?, ?, ?, ?)
            """,
                (entity_clean, entity_content, tags, new_count, now, now),
            )

        for concept in concepts or []:
            concept_clean = concept.strip()
            if not concept_clean:
                continue
            concept_content = f"Concept: {concept_clean}\n\nRelated to: {source_title}"

            conn.execute(
                """
                INSERT OR REPLACE INTO pages (title, content, page_type, tags, source_count, created_at, updated_at)
                VALUES (?, ?, 'concept', ?, 1, ?, ?)
            """,
                (concept_clean, concept_content, tags, now, now),
            )

        conn.commit()

        _log_action(
            "ingest",
            f"{source_title} | entities: {len(entities or [])} | concepts: {len(concepts or [])}",
        )

        return json.dumps(
            {
                "success": True,
                "source_title": source_title,
                "entities_created": len(entities or []),
                "concepts_created": len(concepts or []),
                "message": f"Ingested '{source_title}' into wiki",
            },
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Wiki ingest failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def wiki_query(
    query: str,
    max_results: int = 10,
    page_type: Optional[str] = None,
    task_id: Optional[str] = None,
) -> str:
    """
    Query the wiki for relevant pages.

    Uses FTS5 search to find pages matching the query.

    Args:
        query: What to search for
        max_results: Maximum results (default 10)
        page_type: Optional filter: entity, concept, source, general

    Returns:
        JSON with matching pages
    """
    if not query or not query.strip():
        return json.dumps(
            {"error": "Query is required for wiki search"}, ensure_ascii=False
        )

    query = query.strip()
    conn = _get_db()

    try:
        if page_type:
            sql = """
                SELECT id, title, content, page_type, tags, source_count, updated_at
                FROM pages
                WHERE page_type = ?
                ORDER BY source_count DESC, updated_at DESC
                LIMIT ?
            """
            cursor = conn.execute(sql, (page_type, max_results))
        else:
            sql = """
                SELECT id, title, content, page_type, tags, source_count, updated_at
                FROM pages
                ORDER BY source_count DESC, updated_at DESC
                LIMIT ?
            """
            cursor = conn.execute(sql, (max_results,))

        results = []
        for row in cursor.fetchall():
            content_preview = row[2][:300] + "..." if len(row[2]) > 300 else row[2]
            results.append(
                {
                    "id": row[0],
                    "title": row[1],
                    "content": content_preview,
                    "type": row[3],
                    "tags": row[4],
                    "references": row[5],
                    "updated": row[6],
                }
            )

        if not results:
            return json.dumps(
                {
                    "query": query,
                    "results": [],
                    "message": "No wiki pages found. Use wiki_ingest to add sources.",
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {"query": query, "results": results, "count": len(results)},
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Wiki query failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def wiki_read(
    title: str,
    task_id: Optional[str] = None,
) -> str:
    """
    Read a specific wiki page by title.

    Args:
        title: Exact page title to read

    Returns:
        JSON with full page content
    """
    if not title:
        return json.dumps({"error": "title is required"}, ensure_ascii=False)

    conn = _get_db()

    try:
        cursor = conn.execute(
            """
            SELECT id, title, content, page_type, tags, source_count, created_at, updated_at
            FROM pages WHERE title = ?
        """,
            (title,),
        )

        row = cursor.fetchone()
        if not row:
            return json.dumps(
                {
                    "error": f"Page '{title}' not found",
                    "suggestion": "Use wiki_query to find pages",
                },
                ensure_ascii=False,
            )

        return json.dumps(
            {
                "id": row[0],
                "title": row[1],
                "content": row[2],
                "type": row[3],
                "tags": row[4],
                "references": row[5],
                "created": row[6],
                "updated": row[7],
            },
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Wiki read failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def wiki_update(
    title: str,
    content: str,
    add_tags: str = "",
    task_id: Optional[str] = None,
) -> str:
    """
    Update an existing wiki page.

    Args:
        title: Page title to update
        content: New content
        add_tags: Comma-separated tags to add

    Returns:
        JSON confirmation
    """
    if not title or not content:
        return json.dumps(
            {"error": "title and content are required"}, ensure_ascii=False
        )

    conn = _get_db()

    try:
        now = datetime.now().isoformat()

        existing = conn.execute(
            "SELECT tags FROM pages WHERE title = ?", (title,)
        ).fetchone()
        current_tags = existing[0] if existing else ""

        if add_tags:
            new_tags = list(set(current_tags.split(",") + add_tags.split(",")))
            new_tags = [t.strip() for t in new_tags if t.strip()]
            current_tags = ",".join(new_tags)

        conn.execute(
            """
            UPDATE pages SET content = ?, tags = ?, updated_at = ? WHERE title = ?
        """,
            (content, current_tags, now, title),
        )
        conn.commit()

        _log_action("update", title)

        return json.dumps(
            {"success": True, "title": title, "message": f"Updated page '{title}'"},
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Wiki update failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def wiki_list(
    page_type: Optional[str] = None,
    limit: int = 50,
    task_id: Optional[str] = None,
) -> str:
    """
    List all wiki pages.

    Args:
        page_type: Optional filter
        limit: Max results

    Returns:
        JSON list of pages
    """
    conn = _get_db()

    try:
        if page_type:
            sql = """
                SELECT title, page_type, tags, source_count, updated_at
                FROM pages WHERE page_type = ?
                ORDER BY updated_at DESC LIMIT ?
            """
            cursor = conn.execute(sql, (page_type, limit))
        else:
            sql = """
                SELECT title, page_type, tags, source_count, updated_at
                FROM pages ORDER BY updated_at DESC LIMIT ?
            """
            cursor = conn.execute(sql, (limit,))

        results = []
        for row in cursor.fetchall():
            results.append(
                {
                    "title": row[0],
                    "type": row[1],
                    "tags": row[2],
                    "references": row[3],
                    "updated": row[4],
                }
            )

        return json.dumps({"pages": results, "count": len(results)}, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"error": f"Wiki list failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def wiki_log(
    limit: int = 20,
    task_id: Optional[str] = None,
) -> str:
    """
    Get recent wiki activity log.

    Args:
        limit: Number of entries

    Returns:
        JSON log entries
    """
    conn = _get_db()

    try:
        cursor = conn.execute(
            """
            SELECT timestamp, action, details FROM log
            ORDER BY timestamp DESC LIMIT ?
        """,
            (limit,),
        )

        results = []
        for row in cursor.fetchall():
            results.append({"timestamp": row[0], "action": row[1], "details": row[2]})

        return json.dumps({"log": results, "count": len(results)}, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"error": f"Wiki log failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def wiki_index(
    task_id: Optional[str] = None,
) -> str:
    """
    Generate the wiki index as markdown.

    Returns:
        JSON with index content
    """
    conn = _get_db()

    try:
        entities = conn.execute("""
            SELECT title, tags, source_count FROM pages WHERE page_type = 'entity'
            ORDER BY source_count DESC LIMIT 20
        """).fetchall()

        concepts = conn.execute("""
            SELECT title, tags FROM pages WHERE page_type = 'concept'
            ORDER BY updated_at DESC LIMIT 20
        """).fetchall()

        sources = conn.execute("""
            SELECT title, tags, updated_at FROM pages WHERE page_type = 'source'
            ORDER BY updated_at DESC LIMIT 20
        """).fetchall()

        index_md = "# Wiki Index\n\n"
        index_md += "## Entities (most referenced)\n"
        for row in entities:
            index_md += f"- [[{row[0]}]] ({row[2]} refs) [{row[1]}]\n"

        index_md += "\n## Concepts\n"
        for row in concepts:
            index_md += f"- [[{row[0]}]] [{row[1]}]\n"

        index_md += "\n## Sources\n"
        for row in sources:
            index_md += f"- [[{row[0]}]] ({row[2]})\n"

        return json.dumps(
            {
                "index": index_md,
                "entities": len(entities),
                "concepts": len(concepts),
                "sources": len(sources),
            },
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"Wiki index failed: {e}"}, ensure_ascii=False)
    finally:
        conn.close()


def check_wiki_requirements() -> bool:
    """Always available - uses local SQLite."""
    return True


# =============================================================================
# Tool Schemas
# =============================================================================

WIKI_INGEST_SCHEMA = {
    "name": "wiki_ingest",
    "description": (
        "Ingest a new source into your personal wiki. "
        "The wiki is a persistent, compounding knowledge base - "
        "knowledge is compiled once and kept current, not re-derived every query.\n\n"
        "Use this when:\n"
        "- Reading a book or article worth remembering\n"
        "- Taking notes from a meeting or call\n"
        "- Learning something new worth compiling\n\n"
        "Creates a source page, extracts entity pages, and updates the index."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "source_title": {
                "type": "string",
                "description": "Name/title of the source",
            },
            "source_content": {
                "type": "string",
                "description": "Content or summary to store",
            },
            "entities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Entities to extract (people, projects, tools)",
            },
            "concepts": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Concepts to link",
            },
            "tags": {"type": "string", "description": "Comma-separated tags"},
        },
        "required": ["source_title", "source_content"],
    },
}

WIKI_QUERY_SCHEMA = {
    "name": "wiki_query",
    "description": (
        "Query your wiki for relevant pages. "
        "Search across all entities, concepts, and sources.\n\n"
        "Use this when:\n"
        "- You need to recall something you've learned\n"
        "- Working on a project with specific conventions\n"
        "- Looking for information you previously ingested\n\n"
        "Unlike memory_recall, wiki is for structured knowledge with cross-references."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "What to search for"},
            "max_results": {
                "type": "integer",
                "description": "Max results (default 10)",
                "default": 10,
            },
            "page_type": {
                "type": "string",
                "description": "Filter: entity, concept, source, general",
            },
        },
        "required": ["query"],
    },
}

WIKI_READ_SCHEMA = {
    "name": "wiki_read",
    "description": "Read a specific wiki page by exact title.",
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Exact page title"},
        },
        "required": ["title"],
    },
}

WIKI_UPDATE_SCHEMA = {
    "name": "wiki_update",
    "description": "Update an existing wiki page with new content.",
    "parameters": {
        "type": "object",
        "properties": {
            "title": {"type": "string", "description": "Page title to update"},
            "content": {"type": "string", "description": "New content"},
            "add_tags": {
                "type": "string",
                "description": "Tags to add (comma-separated)",
            },
        },
        "required": ["title", "content"],
    },
}

WIKI_LIST_SCHEMA = {
    "name": "wiki_list",
    "description": "List all wiki pages, optionally filtered by type.",
    "parameters": {
        "type": "object",
        "properties": {
            "page_type": {
                "type": "string",
                "description": "Filter: entity, concept, source, general",
            },
            "limit": {
                "type": "integer",
                "description": "Max results (default 50)",
                "default": 50,
            },
        },
    },
}

WIKI_LOG_SCHEMA = {
    "name": "wiki_log",
    "description": "Get recent wiki activity log (ingests, updates, queries).",
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "description": "Number of entries (default 20)",
                "default": 20,
            },
        },
    },
}

WIKI_INDEX_SCHEMA = {
    "name": "wiki_index",
    "description": "Generate the wiki index as markdown - shows all entities, concepts, and sources.",
    "parameters": {
        "type": "object",
        "properties": {},
    },
}

from tools.registry import registry

registry.register(
    name="wiki_ingest",
    toolset="wiki-memory",
    schema=WIKI_INGEST_SCHEMA,
    handler=lambda args, **kw: wiki_ingest(
        source_title=args.get("source_title", ""),
        source_content=args.get("source_content", ""),
        entities=args.get("entities"),
        concepts=args.get("concepts"),
        tags=args.get("tags", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="Ingest source into personal wiki",
    emoji="📚",
)

registry.register(
    name="wiki_query",
    toolset="wiki-memory",
    schema=WIKI_QUERY_SCHEMA,
    handler=lambda args, **kw: wiki_query(
        query=args.get("query", ""),
        max_results=args.get("max_results", 10),
        page_type=args.get("page_type"),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="Query wiki for relevant pages",
    emoji="🔍",
)

registry.register(
    name="wiki_read",
    toolset="wiki-memory",
    schema=WIKI_READ_SCHEMA,
    handler=lambda args, **kw: wiki_read(
        title=args.get("title", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="Read specific wiki page",
    emoji="📄",
)

registry.register(
    name="wiki_update",
    toolset="wiki-memory",
    schema=WIKI_UPDATE_SCHEMA,
    handler=lambda args, **kw: wiki_update(
        title=args.get("title", ""),
        content=args.get("content", ""),
        add_tags=args.get("add_tags", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="Update wiki page",
    emoji="✏️",
)

registry.register(
    name="wiki_list",
    toolset="wiki-memory",
    schema=WIKI_LIST_SCHEMA,
    handler=lambda args, **kw: wiki_list(
        page_type=args.get("page_type"),
        limit=args.get("limit", 50),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="List all wiki pages",
    emoji="📋",
)

registry.register(
    name="wiki_log",
    toolset="wiki-memory",
    schema=WIKI_LOG_SCHEMA,
    handler=lambda args, **kw: wiki_log(
        limit=args.get("limit", 20),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="Get wiki activity log",
    emoji="📜",
)

registry.register(
    name="wiki_index",
    toolset="wiki-memory",
    schema=WIKI_INDEX_SCHEMA,
    handler=lambda args, **kw: wiki_index(task_id=kw.get("task_id")),
    check_fn=check_wiki_requirements,
    requires_env=[],
    is_async=False,
    description="Generate wiki index",
    emoji="📑",
)
