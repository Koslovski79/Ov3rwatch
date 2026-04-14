#!/bin/bash
# Ov3rwatch startup script - sets up isolated environment from Hermes
# Run this instead of python cli.py to ensure separation from Hermes

export HERMES_HOME="$HOME/.ov3rwatch"
export OVR_HOME="$(pwd)"

# Create config dir if missing
mkdir -p "$HERMES_HOME"

# Run Ov3rwatch
python cli.py "$@"