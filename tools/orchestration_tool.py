#!/usr/bin/env python3
"""
CAI Agent Orchestration Integration for Ov3rwatch
Combines CAI framework (agent patterns, handoffs, guardrails) with HexStrike security tools
"""

import json
import os
import sys

OV3RWATCH_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAI_PATH = os.path.join(OV3RWATCH_PATH, "orchestration")
HEXSTRIKE_PATH = os.path.join(OV3RWATCH_PATH, "hexstrike-ai")


def check_requirements() -> bool:
    """Check if CAI dependencies are available."""
    try:
        from cai.sdk.agents import Agent, Runner

        return True
    except ImportError:
        return False


def get_cai_agents():
    """List available CAI agent patterns."""
    agents = {
        "recon": {
            "description": "Reconnaissance agent - subdomain enum, port scanning, OSINT",
            "tools": ["nmap", "amass", "subfinder", "theharvester"],
        },
        "scanner": {
            "description": "Vulnerability scanner - web app, network, cloud assessment",
            "tools": ["nuclei", "nikto", "sqlmap", "gobuster"],
        },
        "exploit": {
            "description": "Exploitation agent - payload injection, privilege escalation",
            "tools": ["hydra", "john", "netexec"],
        },
        "crypto": {
            "description": "Cryptography agent - hash cracking, encryption analysis",
            "tools": ["hashcat", "john", "openssl"],
        },
        "ctf": {
            "description": "CTF solver - challenge exploitation, flag capture",
            "tools": ["pwntools", "angr", "radare2"],
        },
    }
    return json.dumps(agents)


def get_tool_schema():
    """Return CAI orchestration tool schema."""
    return {
        "name": "cai_orchestrate",
        "description": "Orchestrate CAI agent workflows for cybersecurity tasks - combines agent patterns, handoffs, and HexStrike tools",
        "parameters": {
            "type": "object",
            "properties": {
                "workflow": {
                    "type": "string",
                    "description": "Agent workflow: recon, scan, exploit, ctf, or custom",
                    "enum": ["recon", "scan", "exploit", "ctf", "custom"],
                },
                "target": {
                    "type": "string",
                    "description": "Target host, URL, network, or challenge",
                },
                "mode": {
                    "type": "string",
                    "description": "Execution mode: auto, semi (with HITL), or monitor",
                    "default": "auto",
                },
            },
            "required": ["workflow", "target"],
        },
    }


# Registry entry imported by tools/registry.py
schema = get_tool_schema()


def handler(args, **kwargs):
    """CAI orchestration handler for Ov3rwatch."""
    workflow = args.get("workflow", "")
    target = args.get("target", "")
    mode = args.get("mode", "auto")

    if not workflow or not target:
        return json.dumps({"error": "workflow and target are required"})

    result = {
        "workflow": workflow,
        "target": target,
        "mode": mode,
        "cai_path": CAI_PATH,
        "hexstrike_path": HEXSTRIKE_PATH,
        "status": "integration_ready",
    }

    return json.dumps(result)
