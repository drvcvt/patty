# patty MCP server (optional)

[FastMCP](https://gofastmcp.com) server so Claude Code or other MCP clients can
use patty. Not needed for anything else. Each tool runs
`patty --json <target> <command>` and returns `{exit, items, log}`.

## Setup

```bash
scripts/setup.sh --mcp
```

Creates `mcp/.venv` with fastmcp. Or by hand:

```bash
python3 -m venv mcp/.venv
mcp/.venv/bin/pip install fastmcp
```

Client config, e.g. `.mcp.json`:

```json
{
  "mcpServers": {
    "patty": {
      "command": "/path/to/patty/mcp/.venv/bin/python",
      "args": ["/path/to/patty/mcp/server.py"],
      "env": { "PATTY_EXE": "/home/you/.local/bin/patty" }
    }
  }
}
```

Use the installed binary for `PATTY_EXE`, it has the capability and keeps it
across rebuilds (`build/patty` doesn't).

## Tools

The same names as the shell commands: `ps`, `find`, `findval`, `refs`, `read`,
`probe`, `maps`, `modules`, `check`, plus `command` for any other shell line
(`x/8xg ...`, `filter i32 == 90`). A target is a process name, pid or file.

## Tests

`tests/mcp_smoke.py` runs in `ctest` if `mcp/.venv` with fastmcp exists,
otherwise it's skipped.
