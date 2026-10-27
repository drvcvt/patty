# patty MCP server (optional)

[FastMCP](https://gofastmcp.com) server so Claude Code or other MCP clients can
use patty. Not needed for anything else. It just calls the `patty` binary and
passes the JSON through.

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

`scan_process`, `scan_process_by_pid`, `scan_file`, `multi_scan_process`,
`multi_scan_file`, `scan_with_profile`, `check_profile`, `scan_value`,
`scan_pointer`, `scan_pointers`, `find_string_references`, `probe_object`,
`list_regions`, `dump_memory`.

`check_profile` runs a profile against a target, same as `patty check`.

## Tests

`tests/mcp_smoke.py` runs in `ctest` if `mcp/.venv` with fastmcp exists,
otherwise it's skipped.
