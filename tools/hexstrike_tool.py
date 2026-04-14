#!/usr/bin/env python3
"""
HexStrike Security Tools Integration for Ov3rwatch
Provides 150+ cybersecurity tools through MCP protocol
"""

import json
import os
import subprocess
import sys

OV3RWATCH_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEXSTRIKE_PATH = os.path.join(OV3RWATCH_PATH, "hexstrike-ai", "hexstrike_mcp.py")


def check_requirements() -> bool:
    """Check if HexStrike Python dependencies are available."""
    try:
        import fastmcp
        import aiohttp
        import requests

        return True
    except ImportError:
        return False


def get_tool_schema():
    """Return the HexStrike tool schema for Ov3rwatch."""
    return {
        "name": "hexstrike",
        "description": "Execute 150+ cybersecurity tools (nmap, nuclei, sqlmap, gobuster, etc.) for pentesting, vulnerability discovery, and security research",
        "parameters": {
            "type": "object",
            "properties": {
                "tool": {
                    "type": "string",
                    "description": "Security tool to execute (e.g., nmap, nuclei, gobuster, sqlmap, amass, subfinder)",
                },
                "target": {
                    "type": "string",
                    "description": "Target host, URL, or network to test",
                },
                "args": {
                    "type": "string",
                    "description": "Additional tool arguments (e.g., '-sV -Pn' for nmap)",
                },
            },
            "required": ["tool", "target"],
        },
    }


def hexstrike_exec(tool: str, target: str, args: str = "", task_id: str = None) -> str:
    """Execute a HexStrike security tool."""
    if not os.path.exists(HEXSTRIKE_PATH):
        return json.dumps({"error": "HexStrike not found", "available": False})

    try:
        cmd = [tool, target] + args.split() if args else [tool, target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        return json.dumps(
            {
                "tool": tool,
                "target": target,
                "returncode": result.returncode,
                "stdout": result.stdout[:10000] if result.stdout else "",
                "stderr": result.stderr[:2000] if result.stderr else "",
            }
        )
    except FileNotFoundError:
        return json.dumps({"error": f"Tool not found: {tool}", "available": False})
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Tool execution timeout", "tool": tool})
    except Exception as e:
        return json.dumps({"error": str(e), "tool": tool})


def list_available_tools() -> str:
    """List available HexStrike security tools."""
    tools = {
        "network": ["nmap", "rustscan", "masscan", "autorecon", "amass", "subfinder"],
        "web": [
            "gobuster",
            "feroxbuster",
            "dirsearch",
            "ffuf",
            "nikto",
            "nuclei",
            "sqlmap",
        ],
        "dns": ["fierce", "dnsenum", "theharvester", "recon-ng"],
        "cloud": ["prowler", "scout-suite", "trivy", "kube-hunter"],
        "binary": ["ghidra", "radare2", "gdb", "pwntools", "angr"],
        "password": ["hydra", "john", "hashcat", "medusa", "netexec"],
        "ctf": ["pwntools", "angr", "ropper", "one-gadget"],
    }
    return json.dumps(tools)


# Schema registry - imported by tools/registry.py
schema = get_tool_schema()


def handler(args, **kwargs):
    """HexStrike tool handler for Ov3rwatch."""
    tool = args.get("tool", "")
    target = args.get("target", "")
    args_str = args.get("args", "")
    return hexstrike_exec(tool, target, args_str, kwargs.get("task_id"))
