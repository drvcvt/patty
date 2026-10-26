# patty MCP server (optional)

A small [FastMCP](https://gofastmcp.com) server that lets Claude Code or any
other MCP client drive patty. You don't need it to use patty. It's a thin
wrapper that calls the `patty` binary and passes its JSON output through, so
everything it can do, the CLI can do too.

## Setup

```bash
scripts/setup.sh --mcp
```

That creates `mcp/.venv` with `fastmcp` on top of the normal setup. By hand:

```bash
python3 -m venv mcp/.venv
mcp/.venv/bin/pip install fastmcp
```

Then tell your client about it, e.g. in `.mcp.json`:

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

Point `PATTY_EXE` at the installed binary. That's the one `setup.sh` gave the
capability to read other processes, and unlike `build/patty` it keeps it across
rebuilds.

## Tools

`scan_process`, `scan_process_by_pid`, `scan_file`, `multi_scan_process`,
`multi_scan_file`, `scan_with_profile`, `check_profile`, `scan_value`,
`scan_pointer`, `scan_pointers`, `find_string_references`, `probe_object`,
`list_regions`, `dump_memory`.

`check_profile` is the one worth knowing about: give it a profile and a target,
and it tells the model which signatures survived a game update and where they
point now.

## Tests

`tests/mcp_smoke.py` runs as part of `ctest` whenever `mcp/.venv` exists and has
fastmcp in it. Without the venv the test is skipped and nothing else changes.
