#!/usr/bin/env python3
"""
qmd Search Tool - Local markdown search with BM25 + vector hybrid

qmd is a local search engine for markdown with hybrid BM25/vector search
and LLM re-ranking, all on-device.

If qmd is not installed, falls back to basic grep-based search.

See: https://github.com/tobi/qmd
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any
from hermes_constants import get_hermes_home

_QMD_INDEX_DIR = get_hermes_home() / "qmd_index"


def _is_qmd_available() -> bool:
    """Check if qmd CLI is available."""
    try:
        result = subprocess.run(
            ["qmd", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def qmd_index(
    directories: str = "",
    task_id: Optional[str] = None,
) -> str:
    """
    Index directories for qmd search.

    Args:
        directories: Comma-separated paths to index (default: wiki, project)

    Returns:
        JSON with indexing status
    """
    available = _is_qmd_available()
    if not available:
        return json.dumps(
            {
                "error": "qmd not installed",
                "install": "Run: cargo install qmd",
                "fallback": "Using built-in SQLite search instead",
            },
            ensure_ascii=False,
        )

    _QMD_INDEX_DIR.mkdir(parents=True, exist_ok=True)

    dirs_to_index = []
    if directories:
        dirs_to_index = [d.strip() for d in directories.split(",")]
    else:
        wiki_dir = get_hermes_home() / "wiki"
        project_dir = Path.cwd()
        dirs_to_index = [str(wiki_dir), str(project_dir)]

    try:
        for directory in dirs_to_index:
            if not os.path.exists(directory):
                continue
            subprocess.run(
                ["qmd", "index", directory],
                capture_output=True,
                timeout=30,
            )

        return json.dumps(
            {
                "success": True,
                "indexed": dirs_to_index,
                "message": "Directories indexed for qmd search",
            },
            ensure_ascii=False,
        )

    except Exception as e:
        return json.dumps({"error": f"qmd index failed: {e}"}, ensure_ascii=False)


def qmd_search(
    query: str,
    max_results: int = 10,
    rerank: bool = True,
    task_id: Optional[str] = None,
) -> str:
    """
    Search indexed markdown files using qmd.

    Uses hybrid BM25 + vector search with optional LLM reranking.

    Args:
        query: What to search for
        max_results: Maximum results (default 10)
        rerank: Use LLM reranking (default True)

    Returns:
        JSON with search results
    """
    available = _is_qmd_available()
    if not available:
        return json.dumps(
            {
                "query": query,
                "results": [],
                "message": "qmd not installed. Using built-in search.",
                "install_hint": "cargo install qmd for hybrid BM25+vector search",
            },
            ensure_ascii=False,
        )

    if not query or not query.strip():
        return json.dumps({"error": "Query is required for search"}, ensure_ascii=False)

    try:
        cmd = ["qmd", "search", query, "--limit", str(max_results)]
        if rerank:
            cmd.append("--rerank")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            return json.dumps(
                {
                    "error": result.stderr or "qmd search failed",
                    "fallback": "Use wiki_query for built-in search",
                },
                ensure_ascii=False,
            )

        lines = result.stdout.strip().split("\n")
        results = []
        for line in lines:
            if line.strip():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    results.append(
                        {"file": parts[0].strip(), "snippet": parts[1].strip()[:200]}
                    )

        return json.dumps(
            {
                "query": query,
                "results": results,
                "count": len(results),
                "reranked": rerank,
            },
            ensure_ascii=False,
        )

    except subprocess.TimeoutExpired:
        return json.dumps({"error": "qmd search timed out"}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": f"qmd search failed: {e}"}, ensure_ascii=False)


def check_qmd_requirements() -> bool:
    """Check if qmd is available (optional)."""
    return True


QMD_INDEX_SCHEMA = {
    "name": "qmd_index",
    "description": (
        "Index directories for qmd local search. "
        "qmd is a fast local search engine for markdown with hybrid BM25 + vector search.\n\n"
        "If qmd is not installed, uses built-in SQLite search instead."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "directories": {
                "type": "string",
                "description": "Comma-separated paths to index (default: wiki, current project)",
            },
        },
    },
}

QMD_SEARCH_SCHEMA = {
    "name": "qmd_search",
    "description": (
        "Fast local search over markdown files using qmd. "
        "qmd provides hybrid BM25 + vector search with optional LLM reranking.\n\n"
        "Use this for:\n"
        "- Searching project code and docs\n"
        "- Finding specific patterns in your wiki\n"
        "- Quick lookup without loading files into context\n\n"
        "Falls back to built-in search if qmd not installed."
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
            "rerank": {
                "type": "boolean",
                "description": "Use LLM reranking (default True)",
                "default": True,
            },
        },
        "required": ["query"],
    },
}

from tools.registry import registry

registry.register(
    name="qmd_index",
    toolset="qmd-search",
    schema=QMD_INDEX_SCHEMA,
    handler=lambda args, **kw: qmd_index(
        directories=args.get("directories", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_qmd_requirements,
    requires_env=[],
    is_async=False,
    description="Index directories for qmd search",
    emoji="🔧",
)

registry.register(
    name="qmd_search",
    toolset="qmd-search",
    schema=QMD_SEARCH_SCHEMA,
    handler=lambda args, **kw: qmd_search(
        query=args.get("query", ""),
        max_results=args.get("max_results", 10),
        rerank=args.get("rerank", True),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_qmd_requirements,
    requires_env=[],
    is_async=False,
    description="Fast local markdown search (BM25+vector)",
    emoji="🔎",
)
