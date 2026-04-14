#!/usr/bin/env python3
"""
Strix Integration for Ov3rwatch
Invoke autonomous AI hackers from Ov3rwatch - runs in Docker separately
"""

import json
import os
import subprocess
import sys

OV3RWATCH_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRIX_PATH = "/home/z3r0darkth1rty/strix"


def check_requirements() -> bool:
    """Check if Strix CLI is available."""
    try:
        result = subprocess.run(["which", "strix"], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False


def get_tool_schema():
    """Return Strix pentest tool schema."""
    return {
        "name": "strix",
        "description": "Run Strix autonomous AI hackers for vulnerability discovery. Requires Docker. Use for complex pentests that need real code execution and PoC validation.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target: ./path, https://github.com/org/repo, or https://your-app.com",
                },
                "scan_mode": {
                    "type": "string",
                    "description": "Scan mode: quick, standard, or comprehensive",
                    "default": "standard",
                },
                "instruction": {
                    "type": "string",
                    "description": "Custom instructions for the AI hacker",
                },
            },
            "required": ["target"],
        },
    }


def strix_scan(
    target: str, scan_mode: str = "standard", instruction: str = "", task_id: str = None
) -> str:
    """Run Strix scan."""
    if not os.path.exists(STRIX_PATH):
        return json.dumps(
            {
                "error": "Strix not installed - requires Docker. See https://strix.ai/install"
            }
        )

    try:
        cmd = ["strix", "--target", target]
        if scan_mode:
            cmd.extend(["--scan-mode", scan_mode])
        if instruction:
            cmd.extend(["--instruction", instruction])

        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=STRIX_PATH, timeout=600
        )
        return json.dumps(
            {
                "target": target,
                "scan_mode": scan_mode,
                "returncode": result.returncode,
                "output": result.stdout[:5000] if result.stdout else "",
                "stderr": result.stderr[:2000] if result.stderr else "",
                "docs": "See strix_runs/ directory for full results",
            }
        )
    except FileNotFoundError:
        return json.dumps(
            {
                "error": "Strix CLI not found - install with: curl -sSL https://strix.ai/install | bash"
            }
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Scan timeout - try quick mode"})
    except Exception as e:
        return json.dumps({"error": str(e)})


# Registry entry
schema = get_tool_schema()


def handler(args, **kwargs):
    """Strix handler for Ov3rwatch."""
    target = args.get("target", "")
    scan_mode = args.get("scan_mode", "standard")
    instruction = args.get("instruction", "")
    return strix_scan(target, scan_mode, instruction, kwargs.get("task_id"))
