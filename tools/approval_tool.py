#!/usr/bin/env python3
"""
Enhanced Approval Manager - Safer command execution

Manages command approval rules and dangerous command detection.
Helps the agent understand what requires approval vs what's safe.
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from hermes_constants import get_hermes_home

_APPROVAL_DB_PATH = get_hermes_home() / "approval_rules.json"


def _load_rules() -> Dict[str, Any]:
    """Load approval rules."""
    if _APPROVAL_DB_PATH.exists():
        try:
            return json.loads(_APPROVAL_DB_PATH.read_text())
        except:
            pass
    return {
        "allowlist": [],
        "denylist": [],
        "auto_approve_patterns": [],
        "always_deny_patterns": [],
    }


def _save_rules(rules: Dict[str, Any]) -> None:
    """Save approval rules."""
    _APPROVAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _APPROVAL_DB_PATH.write_text(json.dumps(rules, indent=2))


# Dangerous patterns that should always require approval
ALWAYS_DENY = [
    "rm -rf /",
    "rm -rf ~",
    "dd if=",
    "> /dev/sd",
    "mkfs.",
    "chmod 777 /",
    "chown -R root:",
    ":(){:|:&};:",  # Fork bomb
    "curl | sh",
    "wget -O- | sh",
]

# Safe patterns that can be auto-approved
AUTO_APPROVE = [
    "git status",
    "git log",
    "git diff",
    "ls",
    "pwd",
    "echo",
    "cat ",
    "grep ",
    "find ",
    "head ",
    "tail ",
    "npm install",
    "pip install",
    "python -v",
    "python3 -v",
]


def approval_check(
    command: str,
    task_id: Optional[str] = None,
) -> str:
    """
    Check if a command requires approval or is safe.

    Args:
        command: The shell command to check

    Returns:
        JSON with approval decision and reasoning
    """
    if not command:
        return json.dumps({"error": "No command provided"}, ensure_ascii=False)

    command_lower = command.lower()

    # Check always-deny patterns
    for pattern in ALWAYS_DENY:
        if pattern in command_lower:
            return json.dumps(
                {
                    "command": command,
                    "decision": "deny",
                    "reason": f"Dangerous pattern detected: {pattern}",
                    "requires_approval": True,
                    "auto_approve": False,
                },
                ensure_ascii=False,
            )

    # Check auto-approve patterns
    for pattern in AUTO_APPROVE:
        if command_lower.startswith(pattern) or f" {pattern}" in command_lower:
            return json.dumps(
                {
                    "command": command,
                    "decision": "auto_approve",
                    "reason": f"Safe pattern matched: {pattern}",
                    "requires_approval": False,
                    "auto_approve": True,
                },
                ensure_ascii=False,
            )

    # Load custom rules
    rules = _load_rules()

    # Check custom denylist
    for pattern in rules.get("denylist", []):
        if pattern.lower() in command_lower:
            return json.dumps(
                {
                    "command": command,
                    "decision": "deny",
                    "reason": f"User-denied pattern: {pattern}",
                    "requires_approval": True,
                    "auto_approve": False,
                },
                ensure_ascii=False,
            )

    # Check custom allowlist
    for pattern in rules.get("allowlist", []):
        if pattern.lower() in command_lower:
            return json.dumps(
                {
                    "command": command,
                    "decision": "allow",
                    "reason": f"User-approved pattern: {pattern}",
                    "requires_approval": True,  # Still approval but pre-approved
                    "auto_approve": True,
                },
                ensure_ascii=False,
            )

    # Default: require approval for unknown commands
    return json.dumps(
        {
            "command": command,
            "decision": "review",
            "reason": "Unknown command type - manual review recommended",
            "requires_approval": True,
            "auto_approve": False,
            "safe_patterns": AUTO_APPROVE[:5],
        },
        ensure_ascii=False,
    )


def approval_add_allowlist(
    pattern: str,
    task_id: Optional[str] = None,
) -> str:
    """
    Add a pattern to the approval allowlist (permanent approval).

    Args:
        pattern: Command pattern to always allow

    Returns:
        JSON confirmation
    """
    rules = _load_rules()
    if pattern not in rules.get("allowlist", []):
        rules.setdefault("allowlist", []).append(pattern)
        _save_rules(rules)

    return json.dumps(
        {
            "success": True,
            "action": "added_to_allowlist",
            "pattern": pattern,
            "total_allowed": len(rules.get("allowlist", [])),
        },
        ensure_ascii=False,
    )


def approval_add_denylist(
    pattern: str,
    task_id: Optional[str] = None,
) -> str:
    """
    Add a pattern to the approval denylist (permanent deny).

    Args:
        pattern: Command pattern to always deny

    Returns:
        JSON confirmation
    """
    rules = _load_rules()
    if pattern not in rules.get("denylist", []):
        rules.setdefault("denylist", []).append(pattern)
        _save_rules(rules)

    return json.dumps(
        {
            "success": True,
            "action": "added_to_denylist",
            "pattern": pattern,
            "total_denied": len(rules.get("denylist", [])),
        },
        ensure_ascii=False,
    )


def approval_list_rules(
    task_id: Optional[str] = None,
) -> str:
    """List all approval rules."""
    rules = _load_rules()

    return json.dumps(
        {
            "allowlist": rules.get("allowlist", []),
            "denylist": rules.get("denylist", []),
            "auto_approve_patterns": AUTO_APPROVE,
            "always_deny_patterns": ALWAYS_DENY,
        },
        ensure_ascii=False,
    )


def approval_clear_denylist(
    task_id: Optional[str] = None,
) -> str:
    """Clear all custom denylist rules."""
    rules = _load_rules()
    rules["denylist"] = []
    _save_rules(rules)

    return json.dumps(
        {"success": True, "action": "cleared_denylist"}, ensure_ascii=False
    )


APPROVAL_CHECK_SCHEMA = {
    "name": "approval_check",
    "description": (
        "Check if a command requires approval or is safe to run. "
        "Returns decision: auto_approve, review, or deny.\n\n"
        "Use this before executing shell commands to understand approval requirements."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command to check"},
        },
        "required": ["command"],
    },
}

APPROVAL_ADD_ALLOWLIST_SCHEMA = {
    "name": "approval_add_allowlist",
    "description": "Add a command pattern to permanent allowlist (always approved).",
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Command pattern to allow"},
        },
        "required": ["pattern"],
    },
}

APPROVAL_ADD_DENYLIST_SCHEMA = {
    "name": "approval_add_denylist",
    "description": "Add a command pattern to permanent denylist (always denied).",
    "parameters": {
        "type": "object",
        "properties": {
            "pattern": {"type": "string", "description": "Command pattern to deny"},
        },
        "required": ["pattern"],
    },
}

APPROVAL_LIST_SCHEMA = {
    "name": "approval_list_rules",
    "description": "List all approval rules - allowlist, denylist, auto-approve, always-deny patterns.",
    "parameters": {
        "type": "object",
        "properties": {},
    },
}


from tools.registry import registry

registry.register(
    name="approval_check",
    toolset="approval",
    schema=APPROVAL_CHECK_SCHEMA,
    handler=lambda args, **kw: approval_check(
        command=args.get("command", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Check if command needs approval",
    emoji="✅",
)

registry.register(
    name="approval_add_allowlist",
    toolset="approval",
    schema=APPROVAL_ADD_ALLOWLIST_SCHEMA,
    handler=lambda args, **kw: approval_add_allowlist(
        pattern=args.get("pattern", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Add pattern to permanent allowlist",
    emoji="✔️",
)

registry.register(
    name="approval_add_denylist",
    toolset="approval",
    schema=APPROVAL_ADD_DENYLIST_SCHEMA,
    handler=lambda args, **kw: approval_add_denylist(
        pattern=args.get("pattern", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Add pattern to permanent denylist",
    emoji="🚫",
)

registry.register(
    name="approval_list_rules",
    toolset="approval",
    schema=APPROVAL_LIST_SCHEMA,
    handler=lambda args, **kw: approval_list_rules(task_id=kw.get("task_id")),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="List all approval rules",
    emoji="📋",
)

registry.register(
    name="approval_clear_denylist",
    toolset="approval",
    schema={
        "name": "approval_clear_denylist",
        "description": "Clear all custom denylist rules",
        "parameters": {"type": "object", "properties": {}},
    },
    handler=lambda args, **kw: approval_clear_denylist(task_id=kw.get("task_id")),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Clear denylist rules",
    emoji="🧹",
)
