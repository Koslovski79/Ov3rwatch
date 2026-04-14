# Ov3rwatch WebUI - Forked from hermes-webui

## Overview

This is a fork of [nesquena/hermes-webui](https://github.com/nesquena/hermes-webui) adapted for Ov3rwatch multi-agent control tower.

## Current Status

### ✅ Completed
- Cloned hermes-webui
- Renamed to Ov3rwatch WebUI
- Added API extensions for agent management (`api/agents.py`)
- Initial README

### 🔄 In Progress
- Adding Agents panel to the UI
- Connecting agent registry to web endpoints

### 📋 To Do
1. **Frontend** - Add Agents panel to `panels.js`
2. **API** - Integrate `api/agents.py` with `server.py`
3. **Models** - Connect model dropdown to `list_available_models`
4. **Styling** - Apply 80s hacker theme to UI

## Running

```bash
cd ov3rwatch-webui
python3 bootstrap.py
# or
./start.sh
```

## Key Files Changed

| File | Purpose |
|------|---------|
| `api/agents.py` | Agent CRUD + model listing endpoints |
| `static/panels.js` | Add Agents panel (TODO) |
| `server.py` | Add agent routes (TODO) |

## Architecture

```
ov3rwatch-webui/
├── api/
│   └── agents.py       # NEW: Agent management endpoints
├── static/
│   ├── index.html      # Main UI (needs agents tab)
│   ├── panels.js       # Add agents panel (TODO)
│   └── ui.js           # Frontend logic
├── server.py           # Add /api/agents routes (TODO)
└── README.md           # This file
```

## Connecting to Ov3rwatch Agent

The web UI needs to find the Ov3rwatch agent at:
- `HERMES_WEBUI_AGENT_DIR` env var, or
- `~/.hermes/hermes-agent`, or  
- `../hermes-agent` sibling directory

The agent registry lives at:
- `~/.hermes/agent_registry.json`

## Next Steps

1. **Integrate API**: Add agent routes to `server.py`
2. **Add UI Panel**: Add "Agents" tab to sidebar
3. **Model Dropdown**: Connect to `list_available_models`
4. **Task Submission**: Add task creation UI