# Ov3rwatch Multi-Agent Control Tower - Data Models

## Overview
- **Project**: Ov3rwatch Control Tower
- **Purpose**: Multi-agent management system with company-like structure
- **Inspiration**: hermes-webui + paperclip + OpenClaw

---

## Core Entities

### 1. Organization (Company/Tenant)
```python
Organization {
    id: UUID (primary key)
    name: str                    # Company name
    slug: str                    # URL-friendly identifier
    created_at: datetime
    updated_at: datetime
    settings: JSON               # Company-wide settings
    logo_url: str               # Company logo
    plan: str                   # free, pro, enterprise
    billing_email: str
}
```

### 2. User
```python
User {
    id: UUID
    organization_id: FK -> Organization
    email: str
    name: str
    avatar_url: str
    role: str                   # admin, manager, member, viewer
    status: str                 # active, suspended
    created_at: datetime
    last_login: datetime
    settings: JSON             # User preferences
}
```

### 3. Agent (Worker Instance)
```python
Agent {
    id: UUID
    organization_id: FK -> Organization
    name: str                  # e.g., "Code Agent", "Research Agent"
    description: str
    
    # Configuration
    model: str                 # e.g., "anthropic/claude-sonnet-4-5"
    provider: str             # e.g., "anthropic", "openai"
    
    # Tools & Capabilities
    enabled_toolsets: JSON     # List of toolset names
    custom_prompt: str         # Custom system prompt
    personality: str           # Agent personality/tone
    
    # Status
    status: str               # active, idle, offline, error
    current_task_id: FK -> Task
    
    # Resource Limits
    max_concurrent_tasks: int
    timeout_minutes: int
    
    # Appearance (for UI)
    emoji: str                 # Agent icon
    color: str                 # Brand color
    
    created_at: datetime
    updated_at: datetime
}
```

### 4. Task
```python
Task {
    id: UUID
    organization_id: FK -> Organization
    agent_id: FK -> Agent
    
    # Task Details
    title: str
    description: str
    payload: JSON              # Task input/parameters
    
    # Assignment
    assigned_by: FK -> User
    priority: str              # low, medium, high, urgent
    
    # Status Tracking
    status: str               # queued, assigned, running, completed, failed, cancelled
    result: JSON              # Task output
    error_message: str
    
    # Timing
    created_at: datetime
    started_at: datetime
    completed_at: datetime
    
    # Context
    parent_task_id: FK -> Task  # For sub-tasks
    session_id: str           # Hermes session ID
}
```

### 5. Team/Department
```python
Team {
    id: UUID
    organization_id: FK -> Organization
    name: str
    description: str
    
    # Hierarchy
    parent_team_id: FK -> Team  # For sub-teams
    lead_user_id: FK -> User
    
    # Team Agents
    agent_ids: JSON           # List of agent IDs
    
    # Settings
    default_agent_id: FK -> Agent
    auto_assign: bool
    
    created_at: datetime
}
```

### 6. Workspace
```python
Workspace {
    id: UUID
    organization_id: FK -> Organization
    
    name: str
    path: str                  # File system path
    description: str
    
    # Access Control
    team_ids: JSON            # Which teams have access
    user_ids: JSON           # Individual users
    
    # Settings
    default_agent_id: FK -> Agent
    
    created_at: datetime
}
```

### 7. Session (Conversation)
```python
Session {
    id: UUID
    organization_id: FK -> Organization
    task_id: FK -> Task
    agent_id: FK -> Agent
    
    title: str
    messages: JSON           # Message history
    
    # Metrics
    input_tokens: int
    output_tokens: int
    estimated_cost: float
    
    # Status
    status: str               # active, archived
    
    created_at: datetime
    updated_at: datetime
}
```

---

## API Endpoints Structure

### Organization
```
GET    /api/v1/organizations
GET    /api/v1/organizations/{id}
PATCH  /api/v1/organizations/{id}
DELETE /api/v1/organizations/{id}
```

### Users
```
GET    /api/v1/users
POST   /api/v1/users
GET    /api/v1/users/{id}
PATCH  /api/v1/users/{id}
DELETE /api/v1/users/{id}
POST   /api/v1/users/{id}/invite
```

### Agents
```
GET    /api/v1/agents
POST   /api/v1/agents
GET    /api/v1/agents/{id}
PATCH  /api/v1/agents/{id}
DELETE /api/v1/agents/{id}
POST   /api/v1/agents/{id}/start
POST   /api/v1/agents/{id}/stop
GET    /api/v1/agents/{id}/status
GET    /api/v1/agents/{id}/tasks
```

### Tasks
```
GET    /api/v1/tasks
POST   /api/v1/tasks              # Submit new task
GET    /api/v1/tasks/{id}
PATCH  /api/v1/tasks/{id}
DELETE /api/v1/tasks/{id}
POST   /api/v1/tasks/{id}/cancel
GET    /api/v1/tasks/{id}/result
```

### Teams
```
GET    /api/v1/teams
POST   /api/v1/teams
GET    /api/v1/teams/{id}
PATCH  /api/v1/teams/{id}
DELETE /api/v1/teams/{id}
POST   /api/v1/teams/{id}/agents  # Add agent to team
DELETE /api/v1/teams/{id}/agents/{agent_id}
```

### Workspaces
```
GET    /api/v1/workspaces
POST   /api/v1/workspaces
GET    /api/v1/workspaces/{id}
PATCH  /api/v1/workspaces/{id}
DELETE /api/v1/workspaces/{id}
GET    /api/v1/workspaces/{id}/files
POST   /api/v1/workspaces/{id}/files
```

---

## Web UI Pages

### 1. Dashboard (`/`)
- Organization overview
- Active agents status
- Recent tasks
- Quick actions

### 2. Agents (`/agents`)
- Agent list with status
- Create/edit agent
- Agent configuration
- Performance metrics

### 3. Tasks (`/tasks`)
- Task queue
- Task history
- Create task form
- Task details view

### 4. Teams (`/teams`)
- Team management
- Team members
- Team agents

### 5. Workspaces (`/workspaces`)
- Workspace file browser
- Create workspace
- Access control

### 6. Settings (`/settings`)
- Organization settings
- User management
- Billing (future)
- API keys

---

## Tech Stack Recommendation

### Backend
- **FastAPI** - Modern, fast Python web framework
- **SQLAlchemy** - ORM for database
- **PostgreSQL** - Primary database
- **Redis** - Task queue caching

### Frontend
- **React** - UI framework
- **Paperclip-like** - Component library (custom)
- **SSE** - Real-time updates

### Deployment
- **Docker** - Containerization
- **Gunicorn + Uvicorn** - WSGI/ASGI

---

## Next Steps

1. Create database migration scripts
2. Build agent registry API
3. Set up basic web UI skeleton
4. Integrate with Ov3rwatch core

---

## Notes

- All entities have soft delete capability
- Audit logging for compliance
- API versioning from day one
- WebSocket for real-time task updates