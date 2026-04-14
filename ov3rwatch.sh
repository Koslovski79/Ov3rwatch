#!/bin/bash
# Ov3rwatch startup script - sets up isolated environment from Ov3rwatch
# Run this instead of python cli.py to ensure separation from Ov3rwatch

export HERMES_HOME="$HOME/.ov3rwatch"
export OVR_HOME="$(pwd)"

# Create config dir if missing
mkdir -p "$HERMES_HOME"

# Use venv if exists, otherwise fall back to system python
if [ -d "venv" ]; then
    VENV_PYTHON="./venv/bin/python"
else
    VENV_PYTHON="python3"
fi

# Run Ov3rwatch
$VENV_PYTHON cli.py "$@"