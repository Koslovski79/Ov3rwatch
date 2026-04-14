#!/usr/bin/env python3
"""
OpenCode Tool - Use OpenCode CLI for code analysis and tasks

OpenCode provides deep code understanding via LSP (Language Server Protocol),
making it ideal for complex code analysis, refactoring, and understanding
large codebases.

This tool wraps the `opencode run` command.
"""

import json
import os
import subprocess
import tempfile
from typing import Optional


def opencode_tool(
    prompt: str,
    model: Optional[str] = None,
    session_id: Optional[str] = None,
    task_id: Optional[str] = None,
) -> str:
    """
    Run OpenCode to perform coding tasks with deep LSP understanding.

    Args:
        prompt: The task/instruction for OpenCode
        model: Optional model to use (e.g., "anthropic/claude-sonnet-4-5")
        session_id: Optional session for continuity
        task_id: Task identifier for tracking

    Returns:
        JSON string with OpenCode's response
    """
    if not prompt or not prompt.strip():
        return json.dumps(
            {"error": "Prompt is required for OpenCode tool"}, ensure_ascii=False
        )

    prompt = prompt.strip()

    cmd = ["opencode", "run"]

    if model:
        cmd.extend(["--model", model])

    if session_id:
        cmd.extend(["--session", session_id])

    cmd.extend(["--format", "json"])

    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=os.getcwd(),
        )

        if result.returncode != 0:
            return json.dumps(
                {
                    "error": result.stderr or "OpenCode execution failed",
                    "exit_code": result.returncode,
                },
                ensure_ascii=False,
            )

        output = result.stdout.strip()
        if not output:
            return json.dumps(
                {"error": "OpenCode returned empty response"}, ensure_ascii=False
            )

        responses = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                responses.append(parsed)
            except json.JSONDecodeError:
                responses.append({"raw": line})

        return json.dumps(
            {
                "success": True,
                "responses": responses,
                "session_id": session_id,
            },
            ensure_ascii=False,
        )

    except subprocess.TimeoutExpired:
        return json.dumps(
            {"error": "OpenCode timed out after 5 minutes"}, ensure_ascii=False
        )
    except FileNotFoundError:
        return json.dumps(
            {"error": "OpenCode not found. Install with: npm install -g opencode-cli"},
            ensure_ascii=False,
        )
    except Exception as exc:
        return json.dumps({"error": f"OpenCode failed: {exc}"}, ensure_ascii=False)


def check_opencode_requirements() -> bool:
    """Check if OpenCode CLI is available."""
    try:
        result = subprocess.run(
            ["opencode", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


OPENCODE_SCHEMA = {
    "name": "opencode",
    "description": (
        "Use OpenCode CLI for deep code analysis with LSP support. "
        "Best for: understanding complex codebases, refactoring, "
        "finding definitions, analyzing code structure. "
        "This tool provides deeper code understanding than standard tools."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "prompt": {
                "type": "string",
                "description": "The task or question for OpenCode (e.g., 'Explain the auth flow in this codebase')",
            },
            "model": {
                "type": "string",
                "description": "Optional model override (e.g., 'anthropic/claude-sonnet-4-5', 'openai/gpt-4o')",
            },
            "session_id": {
                "type": "string",
                "description": "Optional session ID for conversation continuity across multiple calls",
            },
        },
        "required": ["prompt"],
    },
}

from tools.registry import registry

registry.register(
    name="opencode",
    toolset="opencode",
    schema=OPENCODE_SCHEMA,
    handler=lambda args, **kw: opencode_tool(
        prompt=args.get("prompt", ""),
        model=args.get("model"),
        session_id=args.get("session_id"),
        task_id=kw.get("task_id"),
    ),
    check_fn=check_opencode_requirements,
    requires_env=[],
    is_async=False,
    description="Use OpenCode CLI for deep code analysis with LSP support",
    emoji="🔮",
)
