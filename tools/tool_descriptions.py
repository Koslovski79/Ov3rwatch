#!/usr/bin/env python3
"""
Tool Description Enhancer - Better tool schemas for smarter tool selection

This file improves tool descriptions to help the LLM agent pick the right tool
for each job. Better descriptions = better tool selection = fewer errors.
"""

from tools.registry import registry


# Enhanced tool descriptions
ENHANCED_DESCRIPTIONS = {
    "terminal": {
        "description": (
            "Execute shell commands in terminal. Use for:\n"
            "- Running git commands (git status, git log, etc.)\n"
            "- Running build tools (npm, pip, cargo, etc.)\n"
            "- System operations (ls, cat, grep, find, etc.)\n"
            "- Installing packages\n"
            "- Running scripts\n\n"
            "DO NOT use for: reading files (use read_file), writing files (use write_file), "
            "or searching code (use search_files)."
        )
    },
    "read_file": {
        "description": (
            "Read file contents from filesystem. Use for:\n"
            "- Reading source code files\n"
            "- Reading config files\n"
            "- Reading documentation\n"
            "- Viewing any text-based file\n\n"
            "DO NOT use for: directories (use terminal with ls), "
            "or binary files (use web search for docs instead)."
        )
    },
    "write_file": {
        "description": (
            "Create or overwrite a file with content. Use for:\n"
            "- Writing source code\n"
            "- Creating config files\n"
            "- Writing documentation\n"
            "- Creating new files\n\n"
            "DO NOT use for: appending to files (use patch or terminal with >>), "
            "or creating directories (use terminal with mkdir)."
        )
    },
    "search_files": {
        "description": (
            "Search for text patterns across files. Use for:\n"
            "- Finding function definitions\n"
            "- Finding import statements\n"
            "- Finding variable usage\n"
            "- Finding TODO comments\n"
            "- Regex pattern matching\n\n"
            "DO NOT use for: reading single files (use read_file), "
            "or searching the web (use web_search)."
        )
    },
    "web_search": {
        "description": (
            "Search the web for information. Use for:\n"
            "- Looking up documentation\n"
            "- Finding solutions to errors\n"
            "- Researching libraries/frameworks\n"
            "- Finding code examples\n"
            "- Getting latest information\n\n"
            "DO NOT use for: searching local files (use search_files), "
            "or extracting content from specific URLs (use web_extract)."
        )
    },
    "web_extract": {
        "description": (
            "Extract and parse content from specific URLs. Use for:\n"
            "- Reading blog posts\n"
            "- Getting documentation from URLs\n"
            "- Extracting article content\n"
            "- Parsing API docs\n\n"
            "DO NOT use for: general searching (use web_search), "
            "or searching local files (use search_files)."
        )
    },
    "memory_recall": {
        "description": (
            "On-demand memory search - retrieves stored facts and preferences. "
            "Use when:\n"
            "- User mentions something you should remember\n"
            "- Working on a project with specific conventions\n"
            "- User corrects you (store the correction with memory_store)\n\n"
            "This does NOT auto-load memories into context. "
            "Call this tool explicitly when you need specific memories. "
            "Zero token cost when not used."
        )
    },
    "memory_store": {
        "description": (
            "Save important information to persistent memory. Use when:\n"
            "- User shares a preference or correction\n"
            "- You learn project-specific facts\n"
            "- You discover environment details worth remembering\n\n"
            "Be concise and factual. Do NOT store task progress or temporary info."
        )
    },
    "wiki_ingest": {
        "description": (
            "Ingest knowledge into your personal wiki. Use for:\n"
            "- Storing knowledge from documents/books\n"
            "- Creating structured notes with entities\n"
            "- Building a knowledge base over time\n\n"
            "Creates source pages, extracts entities/concepts, updates index. "
            "Unlike memory_store (quick facts), wiki is for structured knowledge "
            "with cross-references."
        )
    },
    "wiki_query": {
        "description": (
            "Query your personal wiki for structured knowledge. Use when:\n"
            "- You need to recall organized information\n"
            "- Working with concepts and entities\n"
            "- Looking for synthesized knowledge\n\n"
            "Searches across all wiki pages (entities, concepts, sources)."
        )
    },
    "opencode": {
        "description": (
            "Use OpenCode CLI for deep code analysis. Use when:\n"
            "- You need LSP-powered code understanding\n"
            "- Finding function/class definitions across large codebases\n"
            "- Complex refactoring that needs structural understanding\n"
            "- Understanding unknown code patterns\n\n"
            "This provides deeper code understanding than standard tools. "
            "Use regular tools for simple file operations."
        )
    },
    "browser_navigate": {
        "description": (
            "Navigate to URLs and interact with web pages. Use for:\n"
            "- Visiting websites\n"
            "- Filling forms\n"
            "- Clicking elements\n"
            "- Capturing screenshots\n\n"
            "DO NOT use for: simple content retrieval (use web_extract), "
            "or searching the web (use web_search)."
        )
    },
    "execute_code": {
        "description": (
            "Execute Python code in sandboxed environment. Use for:\n"
            "- Running Python scripts\n"
            "- Testing code snippets\n"
            "- Data processing\n"
            "- Quick calculations\n\n"
            "DO NOT use for: shell commands (use terminal), "
            "or non-Python languages (use appropriate terminal commands)."
        )
    },
    "delegate_task": {
        "description": (
            "Delegate a subtask to a subagent. Use when:\n"
            "- Task can be parallelized\n"
            "- Complex task needs focused attention\n"
            "- Want to explore multiple approaches\n\n"
            "The subagent has its own context. Use for focused, "
            "self-contained subtasks, not for sequential steps."
        )
    },
    "session_search": {
        "description": (
            "Search conversation history. Use when:\n"
            "- User references a previous conversation\n"
            "- You need context from past sessions\n"
            "- Looking for past decisions or conclusions\n\n"
            "This searches stored session transcripts for context."
        )
    },
    "supermemory_profile": {
        "description": (
            "Retrieve user profile from Supermemory. Use when:\n"
            "- Starting a new session\n"
            "- User mentions personal preferences\n"
            "- You need to know who you're working with\n\n"
            "Returns static facts (unchanging info) and dynamic context (recent activity). "
            "Only call when relevant - not auto-loaded."
        )
    },
    "supermemory_search": {
        "description": (
            "Semantic search across long-term memory. Use when:\n"
            "- You need context from past conversations\n"
            "- User asks about something they mentioned before\n"
            "- Working on project with established context\n\n"
            "Uses semantic understanding, not just keyword matching."
        )
    },
}


def enhance_tool_descriptions():
    """Apply enhanced descriptions to registered tools."""
    for tool_name, enhanced in ENHANCED_DESCRIPTIONS.items():
        try:
            registry.update_tool_description(tool_name, enhanced.get("description", ""))
        except Exception:
            pass  # Tool might not exist


# Auto-run on import
try:
    enhance_tool_descriptions()
except Exception:
    pass
