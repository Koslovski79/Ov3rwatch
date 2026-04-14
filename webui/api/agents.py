#!/usr/bin/env python3
"""
Ov3rwatch WebUI API Extensions - Agent Management Endpoints

These endpoints extend the hermes-webui server.py to add multi-agent
management capabilities for the Ov3rwatch Control Tower.
"""

import json
import os
from pathlib import Path

# Registry path
HERMES_HOME = os.getenv("HERMES_HOME", os.path.expanduser("~/.hermes"))
REGISTRY_PATH = Path(HERMES_HOME) / "agent_registry.json"


def load_agents():
    """Load agent registry."""
    if REGISTRY_PATH.exists():
        try:
            return json.loads(REGISTRY_PATH.read_text())
        except:
            pass
    return {"agents": {}, "version": "1.0"}


def save_agents(registry):
    """Save agent registry."""
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_PATH.write_text(json.dumps(registry, indent=2))


# ============================================================================
# API Routes - Add these to server.py or create new endpoints
# ============================================================================


def api_list_agents():
    """List all agents - GET /api/agents"""
    registry = load_agents()
    agents = []
    for agent_id, config in registry.get("agents", {}).items():
        agents.append(
            {
                "id": agent_id,
                "name": config.get("name"),
                "description": config.get("description"),
                "model": config.get("model"),
                "provider": config.get("provider"),
                "emoji": config.get("emoji"),
                "color": config.get("color"),
                "status": "active",  # TODO: Check actual status
            }
        )
    return {"agents": agents, "count": len(agents)}


def api_get_agent(agent_id):
    """Get agent details - GET /api/agents/{id}"""
    registry = load_agents()
    agent = registry.get("agents", {}).get(agent_id)
    if not agent:
        return {"error": f"Agent not found: {agent_id}"}, 404
    return {"id": agent_id, **agent}


def api_create_agent(data):
    """Create new agent - POST /api/agents"""
    required = ["id", "name"]
    for field in required:
        if not data.get(field):
            return {"error": f"Missing required field: {field}"}, 400

    registry = load_agents()
    if data["id"] in registry.get("agents", {}):
        return {"error": f"Agent already exists: {data['id']}"}, 400

    registry.setdefault("agents", {})[data["id"]] = {
        "name": data.get("name"),
        "description": data.get("description", ""),
        "model": data.get("model", "anthropic/claude-sonnet-4-5"),
        "provider": data.get("provider", "anthropic"),
        "enabled_toolsets": data.get("enabled_toolsets", ["core"]),
        "personality": data.get("personality", ""),
        "emoji": data.get("emoji", "🤖"),
        "color": data.get("color", "#00FF00"),
        "max_concurrent_tasks": data.get("max_concurrent_tasks", 1),
        "timeout_minutes": data.get("timeout_minutes", 15),
        "custom_config": data.get("custom_config", {}),
    }
    save_agents(registry)
    return {"success": True, "id": data["id"]}


def api_update_agent(agent_id, data):
    """Update agent - PATCH /api/agents/{id}"""
    registry = load_agents()
    if agent_id not in registry.get("agents", {}):
        return {"error": f"Agent not found: {agent_id}"}, 400

    agent = registry["agents"][agent_id]
    for key in [
        "name",
        "description",
        "model",
        "provider",
        "enabled_toolsets",
        "personality",
        "emoji",
        "color",
        "max_concurrent_tasks",
        "timeout_minutes",
    ]:
        if key in data:
            agent[key] = data[key]

    save_agents(registry)
    return {"success": True, "id": agent_id}


def api_delete_agent(agent_id):
    """Delete agent - DELETE /api/agents/{id}"""
    registry = load_agents()
    if agent_id not in registry.get("agents", {}):
        return {"error": f"Agent not found: {agent_id}"}, 400

    del registry["agents"][agent_id]
    save_agents(registry)
    return {"success": True, "deleted": agent_id}


def api_route_task(data):
    """Route task to agent - POST /api/agents/route"""
    task_type = data.get("task_type", "general")
    preferred = data.get("preferred_agent")

    registry = load_agents()
    agents = registry.get("agents", {})

    # Simple routing logic
    routing = {
        "code": ["code", "general"],
        "research": ["research", "general"],
        "creative": ["creative", "general"],
        "general": ["general", "code", "research"],
    }

    candidates = routing.get(task_type, ["general"])

    if preferred and preferred in agents:
        return {"selected_agent": preferred, "config": agents[preferred]}

    for agent_id in candidates:
        if agent_id in agents:
            return {"selected_agent": agent_id, "config": agents[agent_id]}

    return {"error": "No available agents"}


def api_list_models():
    """List available models - GET /api/models"""
    # Import from available_models_tool
    import sys
    from pathlib import Path

    ov3rwatch_path = Path(HERMES_HOME).parent / "Ov3rwatch"
    if ov3rwatch_path.exists():
        sys.path.insert(0, str(ov3rwatch_path))
        try:
            from tools.available_models_tool import get_available_models

            return json.loads(get_available_models("all"))
        except:
            pass

    return {
        "providers": {
            "openrouter": [
                {"id": "anthropic/claude-sonnet-4-5", "name": "Claude Sonnet 4.5"}
            ],
            "ollama": [],
        }
    }


# ============================================================================
# Server Integration
# ============================================================================

"""
To integrate with server.py, add these routes:

from api.agents import (
    api_list_agents, api_get_agent, api_create_agent,
    api_update_agent, api_delete_agent, api_route_task, api_list_models
)

# Add to route handlers:
@app.route("/api/agents", methods=["GET"])
def list_agents():
    return jsonify(api_list_agents())

@app.route("/api/agents", methods=["POST"])
def create_agent():
    return jsonify(api_create_agent(request.json))

@app.route("/api/agents/<agent_id>", methods=["GET"])
def get_agent(agent_id):
    return jsonify(api_get_agent(agent_id))

@app.route("/api/agents/<agent_id>", methods=["PATCH"])
def update_agent(agent_id):
    return jsonify(api_update_agent(agent_id, request.json))

@app.route("/api/agents/<agent_id>", methods=["DELETE"])
def delete_agent(agent_id):
    return jsonify(api_delete_agent(agent_id))

@app.route("/api/agents/route", methods=["POST"])
def route_task():
    return jsonify(api_route_task(request.json))

@app.route("/api/models")
def list_models():
    return jsonify(api_list_models())
"""
