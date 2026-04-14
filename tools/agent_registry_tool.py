#!/usr/bin/env python3
"""
Agent Registry - Multi-agent configuration and management

Defines and manages multiple agents with different configurations,
models, toolsets, and personalities. Enables the control tower to
route tasks to appropriate agents.
"""

import json
import os
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from hermes_constants import get_hermes_home

_REGISTRY_PATH = get_hermes_home() / "agent_registry.json"
_lock = threading.RLock()

# Default agent templates
DEFAULT_AGENTS = {
    "code": {
        "name": "Code Agent",
        "description": "Specialized in coding, debugging, and code review",
        "model": "anthropic/claude-sonnet-4-5",
        "provider": "anthropic",
        "enabled_toolsets": ["code", "file", "terminal", "execute_code"],
        "personality": "Precise, analytical, focuses on correctness",
        "emoji": "💻",
        "color": "#00FF00",
        "max_concurrent_tasks": 2,
        "timeout_minutes": 30,
    },
    "research": {
        "name": "Research Agent",
        "description": "Specialized in web search, documentation, and information gathering",
        "model": "google/gemini-2.0-flash",
        "provider": "google",
        "enabled_toolsets": ["web", "search", "research"],
        "personality": "Thorough, curious, cites sources",
        "emoji": "🔍",
        "color": "#00FFFF",
        "max_concurrent_tasks": 3,
        "timeout_minutes": 20,
    },
    "general": {
        "name": "General Agent",
        "description": "General purpose assistant for conversation and tasks",
        "model": "openai/gpt-4o",
        "provider": "openai",
        "enabled_toolsets": ["core", "memory", "wiki", "file"],
        "personality": "Helpful, concise, friendly",
        "emoji": "⚔️",
        "color": "#00FF41",
        "max_concurrent_tasks": 1,
        "timeout_minutes": 15,
    },
    "creative": {
        "name": "Creative Agent",
        "description": "Specialized in writing, brainstorming, and creative tasks",
        "model": "openai/gpt-4o",
        "provider": "openai",
        "enabled_toolsets": ["core", "creative", "web"],
        "personality": "Imaginative, articulate, creative",
        "emoji": "🎨",
        "color": "#FF00FF",
        "max_concurrent_tasks": 1,
        "timeout_minutes": 25,
    },
}


def _load_registry() -> Dict[str, Any]:
    """Load agent registry from disk."""
    _lock.acquire()
    try:
        if _REGISTRY_PATH.exists():
            try:
                return json.loads(_REGISTRY_PATH.read_text())
            except json.JSONDecodeError:
                pass
        return {"agents": {}, "version": "1.0"}
    finally:
        _lock.release()


def _save_registry(registry: Dict[str, Any]) -> None:
    """Save agent registry to disk."""
    _lock.acquire()
    try:
        _REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _REGISTRY_PATH.write_text(json.dumps(registry, indent=2))
    finally:
        _lock.release()


def register_agent(
    agent_id: str,
    name: str,
    description: str = "",
    model: str = "anthropic/claude-sonnet-4-5",
    provider: str = "anthropic",
    enabled_toolsets: List[str] = None,
    personality: str = "",
    emoji: str = "🤖",
    color: str = "#00FF00",
    max_concurrent_tasks: int = 1,
    timeout_minutes: int = 15,
    custom_config: Dict[str, Any] = None,
    task_id: Optional[str] = None,
) -> str:
    """
    Register a new agent configuration.

    Args:
        agent_id: Unique identifier for the agent
        name: Display name
        description: What the agent does
        model: Model to use (e.g., "anthropic/claude-sonnet-4-5")
        provider: Model provider
        enabled_toolsets: List of toolset names to enable
        personality: Agent personality description
        emoji: Emoji icon for UI
        color: Brand color for UI
        max_concurrent_tasks: Max parallel tasks
        timeout_minutes: Task timeout
        custom_config: Additional configuration

    Returns:
        JSON with registration result
    """
    if not agent_id or not name:
        return json.dumps(
            {"error": "agent_id and name are required"}, ensure_ascii=False
        )

    registry = _load_registry()

    if enabled_toolsets is None:
        enabled_toolsets = ["core"]

    agent_config = {
        "name": name,
        "description": description,
        "model": model,
        "provider": provider,
        "enabled_toolsets": enabled_toolsets,
        "personality": personality,
        "emoji": emoji,
        "color": color,
        "max_concurrent_tasks": max_concurrent_tasks,
        "timeout_minutes": timeout_minutes,
        "custom_config": custom_config or {},
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
    }

    registry["agents"][agent_id] = agent_config
    _save_registry(registry)

    return json.dumps(
        {"success": True, "agent_id": agent_id, "config": agent_config},
        ensure_ascii=False,
    )


def get_agent(agent_id: str, task_id: Optional[str] = None) -> str:
    """Get agent configuration by ID."""
    registry = _load_registry()

    if agent_id not in registry["agents"]:
        return json.dumps({"error": f"Agent not found: {agent_id}"}, ensure_ascii=False)

    return json.dumps(registry["agents"][agent_id], ensure_ascii=False)


def list_agents(task_id: Optional[str] = None) -> str:
    """List all registered agents."""
    registry = _load_registry()

    agents = []
    for agent_id, config in registry["agents"].items():
        agents.append(
            {
                "agent_id": agent_id,
                "name": config.get("name"),
                "description": config.get("description"),
                "model": config.get("model"),
                "emoji": config.get("emoji"),
                "color": config.get("color"),
                "created_at": config.get("created_at"),
            }
        )

    return json.dumps({"agents": agents, "count": len(agents)}, ensure_ascii=False)


def update_agent(
    agent_id: str,
    name: str = None,
    description: str = None,
    model: str = None,
    provider: str = None,
    enabled_toolsets: List[str] = None,
    personality: str = None,
    emoji: str = None,
    color: str = None,
    max_concurrent_tasks: int = None,
    timeout_minutes: int = None,
    custom_config: Dict[str, Any] = None,
    task_id: Optional[str] = None,
) -> str:
    """Update an existing agent configuration."""
    registry = _load_registry()

    if agent_id not in registry["agents"]:
        return json.dumps({"error": f"Agent not found: {agent_id}"}, ensure_ascii=False)

    agent = registry["agents"][agent_id]

    # Update provided fields
    if name is not None:
        agent["name"] = name
    if description is not None:
        agent["description"] = description
    if model is not None:
        agent["model"] = model
    if provider is not None:
        agent["provider"] = provider
    if enabled_toolsets is not None:
        agent["enabled_toolsets"] = enabled_toolsets
    if personality is not None:
        agent["personality"] = personality
    if emoji is not None:
        agent["emoji"] = emoji
    if color is not None:
        agent["color"] = color
    if max_concurrent_tasks is not None:
        agent["max_concurrent_tasks"] = max_concurrent_tasks
    if timeout_minutes is not None:
        agent["timeout_minutes"] = timeout_minutes
    if custom_config is not None:
        agent["custom_config"] = custom_config

    agent["updated_at"] = datetime.now().isoformat()

    _save_registry(registry)

    return json.dumps(
        {"success": True, "agent_id": agent_id, "updated": agent}, ensure_ascii=False
    )


def delete_agent(agent_id: str, task_id: Optional[str] = None) -> str:
    """Delete an agent configuration."""
    registry = _load_registry()

    if agent_id not in registry["agents"]:
        return json.dumps({"error": f"Agent not found: {agent_id}"}, ensure_ascii=False)

    del registry["agents"][agent_id]
    _save_registry(registry)

    return json.dumps({"success": True, "deleted": agent_id}, ensure_ascii=False)


def initialize_default_agents(task_id: Optional[str] = None) -> str:
    """Initialize the registry with default agent templates."""
    registry = _load_registry()

    for agent_id, config in DEFAULT_AGENTS.items():
        if agent_id not in registry["agents"]:
            registry["agents"][agent_id] = config
            registry["agents"][agent_id]["created_at"] = datetime.now().isoformat()
            registry["agents"][agent_id]["updated_at"] = datetime.now().isoformat()

    _save_registry(registry)

    return json.dumps(
        {"success": True, "initialized": list(DEFAULT_AGENTS.keys())},
        ensure_ascii=False,
    )


def route_task(
    task_type: str,
    preferred_agent: str = None,
    task_id: Optional[str] = None,
) -> str:
    """
    Route a task to the appropriate agent based on task type.

    Args:
        task_type: Type of task (code, research, creative, general)
        preferred_agent: Specific agent to use (optional)

    Returns:
        JSON with recommended agent and configuration
    """
    registry = _load_registry()

    # Task type to agent mapping
    task_routing = {
        "code": ["code", "general"],
        "research": ["research", "general"],
        "creative": ["creative", "general"],
        "general": ["general", "code", "research"],
        "debug": ["code", "general"],
        "write": ["creative", "general"],
        "analyze": ["research", "code", "general"],
    }

    # Get candidate agents
    candidates = task_routing.get(task_type, ["general"])

    if preferred_agent and preferred_agent in registry["agents"]:
        return json.dumps(
            {
                "task_type": task_type,
                "selected_agent": preferred_agent,
                "config": registry["agents"][preferred_agent],
            },
            ensure_ascii=False,
        )

    # Find first available agent
    for agent_id in candidates:
        if agent_id in registry["agents"]:
            return json.dumps(
                {
                    "task_type": task_type,
                    "selected_agent": agent_id,
                    "config": registry["agents"][agent_id],
                },
                ensure_ascii=False,
            )

    return json.dumps(
        {"error": "No available agents for task type", "task_type": task_type},
        ensure_ascii=False,
    )


# =============================================================================
# Tool Schemas
# =============================================================================

REGISTER_AGENT_SCHEMA = {
    "name": "agent_register",
    "description": (
        "Register a new agent configuration for the multi-agent system. "
        "Each agent has its own model, toolsets, and personality.\n\n"
        "Use this to create specialized agents for different tasks."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "agent_id": {
                "type": "string",
                "description": "Unique identifier for the agent",
            },
            "name": {"type": "string", "description": "Display name"},
            "description": {"type": "string", "description": "What the agent does"},
            "model": {
                "type": "string",
                "description": "Model to use (e.g., anthropic/claude-sonnet-4-5)",
            },
            "provider": {"type": "string", "description": "Model provider"},
            "enabled_toolsets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Toolsets to enable",
            },
            "personality": {"type": "string", "description": "Agent personality"},
            "emoji": {"type": "string", "description": "Emoji icon", "default": "🤖"},
            "color": {
                "type": "string",
                "description": "Brand color",
                "default": "#00FF00",
            },
            "max_concurrent_tasks": {
                "type": "integer",
                "description": "Max parallel tasks",
                "default": 1,
            },
            "timeout_minutes": {
                "type": "integer",
                "description": "Task timeout",
                "default": 15,
            },
        },
        "required": ["agent_id", "name"],
    },
}

GET_AGENT_SCHEMA = {
    "name": "agent_get",
    "description": "Get configuration for a specific agent by ID.",
    "parameters": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent ID to retrieve"},
        },
        "required": ["agent_id"],
    },
}

LIST_AGENTS_SCHEMA = {
    "name": "agent_list",
    "description": "List all registered agents with their basic info.",
    "parameters": {
        "type": "object",
        "properties": {},
    },
}

UPDATE_AGENT_SCHEMA = {
    "name": "agent_update",
    "description": "Update an existing agent's configuration.",
    "parameters": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent ID to update"},
            "name": {"type": "string", "description": "New name"},
            "model": {"type": "string", "description": "New model"},
            "enabled_toolsets": {
                "type": "array",
                "items": {"type": "string"},
                "description": "New toolsets",
            },
        },
        "required": ["agent_id"],
    },
}

DELETE_AGENT_SCHEMA = {
    "name": "agent_delete",
    "description": "Delete an agent configuration.",
    "parameters": {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string", "description": "Agent ID to delete"},
        },
        "required": ["agent_id"],
    },
}

INIT_DEFAULT_SCHEMA = {
    "name": "agent_init_defaults",
    "description": "Initialize the registry with default agent templates (code, research, general, creative).",
    "parameters": {
        "type": "object",
        "properties": {},
    },
}

ROUTE_TASK_SCHEMA = {
    "name": "agent_route_task",
    "description": (
        "Route a task to the appropriate agent based on task type. "
        "Returns the best-matching agent configuration."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "task_type": {
                "type": "string",
                "description": "Type: code, research, creative, general, debug, write, analyze",
            },
            "preferred_agent": {
                "type": "string",
                "description": "Specific agent to use (optional)",
            },
        },
        "required": ["task_type"],
    },
}


from tools.registry import registry

registry.register(
    name="agent_register",
    toolset="agent-registry",
    schema=REGISTER_AGENT_SCHEMA,
    handler=lambda args, **kw: register_agent(
        agent_id=args.get("agent_id", ""),
        name=args.get("name", ""),
        description=args.get("description", ""),
        model=args.get("model", "anthropic/claude-sonnet-4-5"),
        provider=args.get("provider", "anthropic"),
        enabled_toolsets=args.get("enabled_toolsets"),
        personality=args.get("personality", ""),
        emoji=args.get("emoji", "🤖"),
        color=args.get("color", "#00FF00"),
        max_concurrent_tasks=args.get("max_concurrent_tasks", 1),
        timeout_minutes=args.get("timeout_minutes", 15),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Register a new agent configuration",
    emoji="➕",
)

registry.register(
    name="agent_get",
    toolset="agent-registry",
    schema=GET_AGENT_SCHEMA,
    handler=lambda args, **kw: get_agent(
        agent_id=args.get("agent_id", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Get agent configuration by ID",
    emoji="📋",
)

registry.register(
    name="agent_list",
    toolset="agent-registry",
    schema=LIST_AGENTS_SCHEMA,
    handler=lambda args, **kw: list_agents(task_id=kw.get("task_id")),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="List all registered agents",
    emoji="📃",
)

registry.register(
    name="agent_update",
    toolset="agent-registry",
    schema=UPDATE_AGENT_SCHEMA,
    handler=lambda args, **kw: update_agent(
        agent_id=args.get("agent_id", ""),
        name=args.get("name"),
        description=args.get("description"),
        model=args.get("model"),
        provider=args.get("provider"),
        enabled_toolsets=args.get("enabled_toolsets"),
        personality=args.get("personality"),
        emoji=args.get("emoji"),
        color=args.get("color"),
        max_concurrent_tasks=args.get("max_concurrent_tasks"),
        timeout_minutes=args.get("timeout_minutes"),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Update agent configuration",
    emoji="✏️",
)

registry.register(
    name="agent_delete",
    toolset="agent-registry",
    schema=DELETE_AGENT_SCHEMA,
    handler=lambda args, **kw: delete_agent(
        agent_id=args.get("agent_id", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Delete an agent configuration",
    emoji="🗑️",
)

registry.register(
    name="agent_init_defaults",
    toolset="agent-registry",
    schema=INIT_DEFAULT_SCHEMA,
    handler=lambda args, **kw: initialize_default_agents(task_id=kw.get("task_id")),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Initialize default agent templates",
    emoji="🚀",
)

registry.register(
    name="agent_route_task",
    toolset="agent-registry",
    schema=ROUTE_TASK_SCHEMA,
    handler=lambda args, **kw: route_task(
        task_type=args.get("task_type", ""),
        preferred_agent=args.get("preferred_agent"),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Route task to appropriate agent",
    emoji="🎯",
)
