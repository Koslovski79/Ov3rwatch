# Ov3rwatch Web UI

A modern, dark-themed web interface for Ov3rwatch multi-agent control tower. Built on top of hermes-webui with multi-agent capabilities added.

## Quick Start

```bash
cd ov3rwatch-webui
python3 bootstrap.py
```

Or use the launcher:

```bash
./start.sh
```

The bootstrap will:
1. Detect Ov3rwatch agent
2. Start the web server
3. Open the browser to http://localhost:8787

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OV3RWATCH_WEBUI_PORT` | `8787` | Port to run on |
| `OV3RWATCH_WEBUI_PASSWORD` | *(none)* | Set for password protection |
| `OV3RWATCH_WEBUI_STATE_DIR` | `~/.hermes/webui-mvp` | State directory |
| `HERMES_WEBUI_AGENT_DIR` | auto | Path to Ov3rwatch agent |

## Multi-Agent Features

- **Agent Registry**: Create and manage multiple specialized agents
- **Task Queue**: Submit tasks to specific agents or auto-route
- **Model Selection**: Choose from OpenRouter, Ollama, Anthropic, OpenAI, Google
- **Team Management**: Organize agents into teams/departments

## Architecture

```
server.py              # HTTP routing + auth
api/
  agents.py           # Agent CRUD operations
  tasks.py            # Task management
  routes.py           # All endpoints
static/
  index.html          # Main UI
  ui.js               # Frontend logic
  panels.js           # Multi-agent panels
```

## Docker

```bash
docker build -t ov3rwatch-webui .
docker run -d -p 8787:8789 -v ~/.hermes:/home/hermeswebui/.hermes ov3rwatch-webui
```

## Access

- Local: http://localhost:8787
- Remote: Use SSH tunnel: `ssh -N -L 8787:127.0.0.1:8787 user@server`

---

For full documentation, see [docs/](./docs/).