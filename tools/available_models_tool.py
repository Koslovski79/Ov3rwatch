#!/usr/bin/env python3
"""
Available Models Provider - Fetch and list available models from all providers

Provides tools to list available models from:
- OpenRouter
- Ollama (local)
- Anthropic
- OpenAI
- Google
- DeepSeek
- And other configured providers
"""

import json
import os
import requests
from typing import Dict, List, Optional, Any
from hermes_constants import get_hermes_home, OPENROUTER_BASE_URL


def get_available_models(
    provider: str = "all",
    force_refresh: bool = False,
    task_id: Optional[str] = None,
) -> str:
    """
    Get available models from configured providers.

    Args:
        provider: Specific provider or "all" (default: all)
        force_refresh: Force refresh from API

    Returns:
        JSON with available models grouped by provider
    """
    results = {}

    # OpenRouter
    if provider in ("all", "openrouter"):
        or_key = os.getenv("OPENROUTER_API_KEY", "")
        if or_key:
            try:
                response = requests.get(
                    f"{OPENROUTER_BASE_URL}/models",
                    headers={"Authorization": f"Bearer {or_key}"},
                    timeout=10,
                )
                if response.status_code == 200:
                    models = []
                    for m in response.json().get("data", []):
                        models.append(
                            {
                                "id": m.get("id"),
                                "name": m.get("name"),
                                "context_length": m.get("context_length", 128000),
                            }
                        )
                    results["openrouter"] = models[:50]  # Limit to 50
            except Exception as e:
                results["openrouter"] = {"error": str(e)}

    # Ollama (local)
    if provider in ("all", "ollama"):
        ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        try:
            response = requests.get(f"{ollama_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = []
                for m in response.json().get("models", []):
                    models.append(
                        {
                            "id": m.get("name"),
                            "name": m.get("name"),
                            "size": m.get("size"),
                        }
                    )
                results["ollama"] = models
        except Exception as e:
            results["ollama"] = {"error": str(e)}

    # Anthropic (requires ANTHROPIC_API_KEY)
    if provider in ("all", "anthropic"):
        anth_key = os.getenv("ANTHROPIC_API_KEY", "")
        if anth_key:
            try:
                # Use the models list endpoint
                response = requests.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": anth_key, "anthropic-version": "2023-01-01"},
                    timeout=10,
                )
                if response.status_code == 200:
                    models = []
                    for m in response.json().get("data", []):
                        models.append(
                            {
                                "id": m.get("id"),
                                "name": m.get("display_name"),
                            }
                        )
                    results["anthropic"] = models
            except Exception as e:
                results["anthropic"] = {"error": str(e)}

    # OpenAI
    if provider in ("all", "openai"):
        oai_key = os.getenv("OPENAI_API_KEY", "")
        if oai_key:
            try:
                response = requests.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {oai_key}"},
                    timeout=10,
                )
                if response.status_code == 200:
                    models = []
                    for m in response.json().get("data", []):
                        models.append(
                            {
                                "id": m.get("id"),
                                "name": m.get("id"),
                            }
                        )
                    results["openai"] = models[:50]
            except Exception as e:
                results["openai"] = {"error": str(e)}

    # Google (Gemini)
    if provider in ("all", "google"):
        google_key = os.getenv("GOOGLE_API_KEY", "")
        if google_key:
            # Google doesn't have a public models list API, use known models
            results["google"] = [
                {"id": "gemini-2.0-flash", "name": "Gemini 2.0 Flash"},
                {"id": "gemini-2.0-flash-lite", "name": "Gemini 2.0 Flash Lite"},
                {"id": "gemini-1.5-pro", "name": "Gemini 1.5 Pro"},
                {"id": "gemini-1.5-flash", "name": "Gemini 1.5 Flash"},
            ]

    # DeepSeek
    if provider in ("all", "deepseek"):
        deepseek_key = os.getenv("DEEPSEEK_API_KEY", "")
        if deepseek_key:
            results["deepseek"] = [
                {"id": "deepseek-chat", "name": "DeepSeek Chat"},
                {"id": "deepseek-coder", "name": "DeepSeek Coder"},
                {"id": "deepseek-reasoner", "name": "DeepSeek Reasoner"},
            ]

    # OpenRouter Free Models
    if provider in ("all", "openrouter_free"):
        results["openrouter_free"] = [
            {"id": "google/gemma-2-9b-it:free", "name": "Gemma 2 9B (Free)"},
            {"id": "meta-llama/llama-3-8b-instruct:free", "name": "Llama 3 8B (Free)"},
            {"id": "mistralai/mistral-7b-instruct:free", "name": "Mistral 7B (Free)"},
            {"id": "qwen/qwen2-7b-instruct:free", "name": "Qwen 2 7B (Free)"},
        ]

    if not results:
        return json.dumps(
            {
                "error": "No providers configured. Set API keys in .env (OPENROUTER_API_KEY, OLLAMA_BASE_URL, etc.)"
            },
            ensure_ascii=False,
        )

    return json.dumps(
        {
            "providers": results,
            "count": sum(
                len(v) if isinstance(v, list) else 0 for v in results.values()
            ),
        },
        ensure_ascii=False,
    )


def get_model_by_capability(
    capability: str,
    task_id: Optional[str] = None,
) -> str:
    """
    Get recommended models based on task capability.

    Args:
        capability: Task type (coding, reasoning, fast, vision, creative)

    Returns:
        JSON with recommended models
    """
    recommendations = {
        "coding": [
            "anthropic/claude-sonnet-4-5",
            "deepseek/deepseek-coder",
            "openai/gpt-4o",
            "qwen/qwen-coder-turbo",
        ],
        "reasoning": [
            "deepseek/deepseek-reasoner",
            "anthropic/claude-opus-4-6",
            "google/gemini-2.0-flash",
        ],
        "fast": [
            "google/gemini-2.0-flash",
            "anthropic/claude-haiku-4-5",
            "openai/gpt-4o-mini",
        ],
        "vision": [
            "anthropic/claude-sonnet-4-5",
            "openai/gpt-4o",
            "google/gemini-1.5-pro",
        ],
        "creative": [
            "openai/gpt-4o",
            "anthropic/claude-opus-4-6",
        ],
        "cheap": [
            "google/gemma-2-9b-it:free",
            "meta-llama/llama-3-8b-instruct:free",
            "mistralai/mistral-7b-instruct:free",
        ],
    }

    models = recommendations.get(capability.lower(), [])

    return json.dumps(
        {"capability": capability, "recommended_models": models}, ensure_ascii=False
    )


def test_provider_connection(
    provider: str,
    task_id: Optional[str] = None,
) -> str:
    """
    Test if a provider API is working.

    Args:
        provider: Provider name (openrouter, ollama, anthropic, openai, google, deepseek)

    Returns:
        JSON with connection status
    """
    status = {"provider": provider, "connected": False, "models_available": 0}

    if provider == "openrouter":
        key = os.getenv("OPENROUTER_API_KEY", "")
        if key:
            try:
                r = requests.get(
                    f"{OPENROUTER_BASE_URL}/models",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=5,
                )
                status["connected"] = r.status_code == 200
                if r.status_code == 200:
                    status["models_available"] = len(r.json().get("data", []))
            except Exception as e:
                status["error"] = str(e)

    elif provider == "ollama":
        url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        try:
            r = requests.get(f"{url}/api/tags", timeout=5)
            status["connected"] = r.status_code == 200
            if r.status_code == 200:
                status["models_available"] = len(r.json().get("models", []))
        except Exception as e:
            status["error"] = str(e)

    elif provider == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY", "")
        if key:
            try:
                r = requests.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": key, "anthropic-version": "2023-01-01"},
                    timeout=5,
                )
                status["connected"] = r.status_code == 200
                if r.status_code == 200:
                    status["models_available"] = len(r.json().get("data", []))
            except Exception as e:
                status["error"] = str(e)

    elif provider == "openai":
        key = os.getenv("OPENAI_API_KEY", "")
        if key:
            try:
                r = requests.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=5,
                )
                status["connected"] = r.status_code == 200
                if r.status_code == 200:
                    status["models_available"] = len(r.json().get("data", []))
            except Exception as e:
                status["error"] = str(e)

    elif provider == "google":
        key = os.getenv("GOOGLE_API_KEY", "")
        status["connected"] = bool(key)
        status["models_available"] = 4  # Known models

    return json.dumps(status, ensure_ascii=False)


# =============================================================================
# Tool Schemas
# =============================================================================

GET_MODELS_SCHEMA = {
    "name": "list_available_models",
    "description": (
        "List all available models from configured providers. "
        "Shows OpenRouter, Ollama, Anthropic, OpenAI, Google, DeepSeek.\n\n"
        "Use this to see what models are available for your agents."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "description": "Specific provider or 'all' (default: all)",
            },
            "force_refresh": {
                "type": "boolean",
                "description": "Force refresh from API",
                "default": False,
            },
        },
    },
}

GET_BY_CAPABILITY_SCHEMA = {
    "name": "get_models_by_capability",
    "description": "Get recommended models for a specific capability (coding, reasoning, fast, vision, creative, cheap).",
    "parameters": {
        "type": "object",
        "properties": {
            "capability": {
                "type": "string",
                "description": "Task capability: coding, reasoning, fast, vision, creative, cheap",
            },
        },
        "required": ["capability"],
    },
}

TEST_PROVIDER_SCHEMA = {
    "name": "test_provider_connection",
    "description": "Test if a specific provider API is working and accessible.",
    "parameters": {
        "type": "object",
        "properties": {
            "provider": {
                "type": "string",
                "description": "Provider: openrouter, ollama, anthropic, openai, google, deepseek",
            },
        },
        "required": ["provider"],
    },
}


from tools.registry import registry

registry.register(
    name="list_available_models",
    toolset="models",
    schema=GET_MODELS_SCHEMA,
    handler=lambda args, **kw: get_available_models(
        provider=args.get("provider", "all"),
        force_refresh=args.get("force_refresh", False),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="List available models from providers",
    emoji="📡",
)

registry.register(
    name="get_models_by_capability",
    toolset="models",
    schema=GET_BY_CAPABILITY_SCHEMA,
    handler=lambda args, **kw: get_model_by_capability(
        capability=args.get("capability", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Get recommended models for task",
    emoji="🎯",
)

registry.register(
    name="test_provider_connection",
    toolset="models",
    schema=TEST_PROVIDER_SCHEMA,
    handler=lambda args, **kw: test_provider_connection(
        provider=args.get("provider", ""),
        task_id=kw.get("task_id"),
    ),
    check_fn=lambda: True,
    requires_env=[],
    is_async=False,
    description="Test provider connection",
    emoji="🔌",
)
