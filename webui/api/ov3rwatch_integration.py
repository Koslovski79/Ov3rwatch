#!/usr/bin/env python3
"""
Ov3rwatch Integration Helper

This module provides a clean interface for the web UI to access Ov3rwatch functionality.
Put this in the webui directory and import from here.
"""

import json
import os
import sys
import logging

logger = logging.getLogger(__name__)


# Find Ov3rwatch installation
def _find_ov3rwatch():
    """Find Ov3rwatch installation path."""
    # Hard-coded path as primary - this is where we expect it
    hardcoded = "/home/z3r0darkth1rty/Ov3rwatch"
    if os.path.exists(hardcoded):
        return hardcoded

    # Also check HERMES_HOME relative path
    hermes_home = os.getenv("HERMES_HOME", os.path.expanduser("~/.hermes"))
    relative = os.path.join(os.path.dirname(hermes_home), "Ov3rwatch")
    if os.path.exists(relative):
        return relative

    # Check home directory
    home_path = os.path.expanduser("~/Ov3rwatch")
    if os.path.exists(home_path):
        return home_path

    # Check docker path
    if os.path.exists("/app/ov3rwatch"):
        return "/app/ov3rwatch"

    return None


# Try to load Ov3rwatch tools
_OV3RWATCH_PATH = _find_ov3rwatch()
_OV3RWATCH_LOADED = False

if _OV3RWATCH_PATH:
    if _OV3RWATCH_PATH not in sys.path:
        sys.path.insert(0, _OV3RWATCH_PATH)

    try:
        from tools.agent_registry_tool import (
            list_agents as _list_agents,
            get_agent as _get_agent,
            register_agent as _register_agent,
            update_agent as _update_agent,
            delete_agent as _delete_agent,
            initialize_default_agents as _init_defaults,
            route_task as _route_task,
        )
        from tools.available_models_tool import get_available_models as _get_models

        _OV3RWATCH_LOADED = True
        logger.info(f"Ov3rwatch integration loaded from: {_OV3RWATCH_PATH}")
    except ImportError as e:
        logger.warning(f"Ov3rwatch tools not found: {e}")
else:
    logger.warning("Ov3rwatch installation not found")


# Public API
def is_loaded():
    """Check if Ov3rwatch is loaded."""
    return _OV3RWATCH_LOADED


def get_path():
    """Get Ov3rwatch path."""
    return _OV3RWATCH_PATH


def list_agents():
    """List all agents."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded", "agents": []})
    return _list_agents()


def get_agent(agent_id):
    """Get specific agent."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded"})
    return _get_agent(agent_id)


def create_agent(
    agent_id,
    name,
    description="",
    model="anthropic/claude-sonnet-4-5",
    provider="anthropic",
    enabled_toolsets=None,
    personality="",
    emoji="🤖",
    color="#00FF00",
):
    """Create new agent."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded"})
    return _register_agent(
        agent_id,
        name,
        description,
        model,
        provider,
        enabled_toolsets,
        personality,
        emoji,
        color,
    )


def update_agent(agent_id, **kwargs):
    """Update agent."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded"})
    return _update_agent(agent_id, **kwargs)


def delete_agent(agent_id):
    """Delete agent."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded"})
    return _delete_agent(agent_id)


def initialize_agents():
    """Initialize default agents."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded"})
    return _init_defaults()


def route_task(task_type, preferred_agent=None):
    """Route task to agent."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded"})
    return _route_task(task_type, preferred_agent)


def get_models(provider="all"):
    """Get available models."""
    if not _OV3RWATCH_LOADED:
        return json.dumps({"error": "Ov3rwatch not loaded", "providers": {}})
    return _get_models(provider)


def parse_json(result):
    """Parse JSON result safely."""
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"raw": result}
    return {"error": "Unknown result type"}
