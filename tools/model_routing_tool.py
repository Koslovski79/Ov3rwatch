#!/usr/bin/env python3
"""
Multi-Model Router - Auto-switch models based on task type

Automatically selects the best model for the task:
- Reasoning tasks → use reasoning model
- Fast/simple tasks → use fast model
- Creative tasks → use creative model
- Code tasks → use code-optimized model
"""

import json
import os
from typing import Optional, Dict, Any
from hermes_constants import get_hermes_home

# Model routing rules
MODEL_ROUTING = {
    "reasoning": {
        "description": "Complex reasoning, analysis, debugging",
        "keywords": [
            "why",
            "how",
            "analyze",
            "debug",
            "reason",
            "explain",
            "logic",
            "solve",
            "think",
        ],
        "preferred_models": [
            "anthropic/claude-sonnet-4-5",
            "deepseek/deepseek-r1",
            "qwen/qwen3-32b",
        ],
    },
    "fast": {
        "description": "Quick answers, simple tasks, one-liners",
        "keywords": [
            "what",
            "define",
            "list",
            "simple",
            "quick",
            "echo",
            "hello",
            "time",
        ],
        "preferred_models": [
            "google/gemini-2.0-flash",
            "anthropic/claude-haiku-4-5",
            "openai/gpt-4o-mini",
        ],
    },
    "creative": {
        "description": "Writing, brainstorming, creative tasks",
        "keywords": [
            "write",
            "create",
            "story",
            "poem",
            "brainstorm",
            "idea",
            "design",
            "creative",
        ],
        "preferred_models": [
            "openai/gpt-4o",
            "anthropic/claude-opus-4-6",
            "midjourney",
        ],
    },
    "code": {
        "description": "Coding, refactoring, code review",
        "keywords": [
            "code",
            "function",
            "class",
            "implement",
            "refactor",
            "review",
            "fix",
            "bug",
            "program",
        ],
        "preferred_models": [
            "anthropic/claude-sonnet-4-5",
            "openai/gpt-4o",
            "deepseek/deepseek-coder",
        ],
    },
    "vision": {
        "description": "Image analysis, OCR, visual tasks",
        "keywords": [
            "image",
            "picture",
            "screenshot",
            "visual",
            "see",
            "look",
            "screen",
        ],
        "preferred_models": ["anthropic/claude-sonnet-4-5", "openai/gpt-4o"],
    },
    "default": {
        "description": "General conversation",
        "keywords": [],
        "preferred_models": ["anthropic/claude-sonnet-4-5"],
    },
}


def detect_task_type(message: str) -> str:
    """Detect the primary task type from the message."""
    message_lower = message.lower()

    # Score each category
    scores = {}
    for category, config in MODEL_ROUTING.items():
        if category == "default":
            continue
        score = 0
        for keyword in config["keywords"]:
            if keyword in message_lower:
                score += 1
        scores[category] = score

    # Find highest scoring category
    if scores:
        max_score = max(scores.values())
        if max_score > 0:
            for category, score in scores.items():
                if score == max_score:
                    return category

    return "default"


def route_model(
    message: str,
    current_model: str = "",
    prefer_speed: bool = False,
    prefer_quality: bool = False,
    task_id: Optional[str] = None,
) -> str:
    """
    Analyze message and recommend the best model.

    Args:
        message: The user's message
        current_model: Current model (to avoid switching if similar)
        prefer_speed: Prefer faster models
        prefer_quality: Prefer higher quality models

    Returns:
        JSON with recommended model and reasoning
    """
    task_type = detect_task_type(message)
    config = MODEL_ROUTING.get(task_type, MODEL_ROUTING["default"])

    models = config["preferred_models"]

    # Adjust based on preferences
    if prefer_speed and len(models) > 1:
        selected = models[-1]  # Fastest
    elif prefer_quality and len(models) > 1:
        selected = models[0]  # Best quality
    else:
        selected = models[0]  # Default first choice

    # Don't switch if already using similar model
    if current_model and selected.lower() in current_model.lower():
        return json.dumps(
            {
                "current_model": current_model,
                "recommended_model": current_model,
                "task_type": task_type,
                "reasoning": f"Current model already optimal for {task_type} tasks",
                "switch_recommended": False,
            },
            ensure_ascii=False,
        )

    return json.dumps(
        {
            "current_model": current_model,
            "recommended_model": selected,
            "task_type": task_type,
            "reasoning": f"{task_type} task detected - {config['description']}",
            "switch_recommended": True,
        },
        ensure_ascii=False,
    )


def list_routing_rules(
    task_id: Optional[str] = None,
) -> str:
    """List all routing rules and their triggers."""
    rules = []
    for category, config in MODEL_ROUTING.items():
        if category == "default":
            continue
        rules.append(
            {
                "category": category,
                "description": config["description"],
                "triggers": config["keywords"][:10],  # First 10
                "models": config["preferred_models"],
            }
        )

    return json.dumps(
        {"rules": rules, "default": MODEL_ROUTING["default"]["preferred_models"]},
        ensure_ascii=False,
    )


# This would be used by the CLI to suggest model switches
# Actual implementation would happen in run_agent.py or cli.py


ROUTING_SCHEMA = {
    "name": "route_model",
    "description": (
        "Analyze a message and recommend the best model for the task. "
        "Use this when:\n"
        "- Task is complex reasoning → use reasoning model\n"
        "- Quick answer needed → use fast model\n"
        "- Creative writing → use creative model\n"
        "- Coding task → use code-optimized model\n\n"
        "The router analyzes keywords and suggests the optimal model."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "message": {"type": "string", "description": "User message to analyze"},
            "current_model": {
                "type": "string",
                "description": "Current model (optional)",
            },
            "prefer_speed": {
                "type": "boolean",
                "description": "Prefer faster models",
                "default": False,
            },
            "prefer_quality": {
                "type": "boolean",
                "description": "Prefer highest quality",
                "default": False,
            },
        },
        "required": ["message"],
    },
}

ROUTING_LIST_SCHEMA = {
    "name": "list_routing_rules",
    "description": "List all model routing rules - categories, keywords, and preferred models.",
    "parameters": {
        "type": "object",
        "properties": {},
    },
}


from tools.registry import registry

registry.register(
    name="route_model",
    toolset="model-routing",
    schema=ROUTING_SCHEMA,
    handler=lambda args, **kw: route_model(
        message=args.get("message", ""),
        current_model=args.get("current_model", ""),
        prefer_speed=args.get("prefer_speed", False),
        prefer_quality=args.get("prefer_quality", False),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Auto-route to best model for task",
    emoji="🎯",
)

registry.register(
    name="list_routing_rules",
    toolset="model-routing",
    schema=ROUTING_LIST_SCHEMA,
    handler=lambda args, **kw: list_routing_rules(task_id=kw.get("task_id")),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="List model routing rules",
    emoji="📋",
)
