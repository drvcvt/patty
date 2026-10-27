"""patty MCP server: each tool runs `patty --json <target> <command>`.

Optional. Everything here is also just a shell command; see `patty help`.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP


def _find_patty() -> str:
    if exe := os.environ.get("PATTY_EXE"):
        return exe
    if exe := shutil.which("patty"):
        return exe
    return str(Path(__file__).resolve().parent.parent / "build" / "patty")


PATTY = _find_patty()

mcp = FastMCP(
    "patty",
    instructions=(
        "Read-only memory scanner for running processes and PE/ELF files. A target is a "
        "process name, a pid or a file path. Every tool returns {exit, items, log}: exit 0 "
        "found something, 2 found nothing (or a check was not clean), 1 error. Addresses "
        "are hex strings and can be passed back into other tools, including expressions "
        "like 'Game.exe+0x2A4F10' or '[0x7ff6a0010000]+0x18' ([] reads a pointer)."
    ),
)


def _run(target: Optional[str], *command: str, timeout: int = 300) -> dict:
    args = [PATTY, "--json", *([target] if target else []), *command]
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {"exit": 1, "items": [], "log": f"patty not found at {PATTY}, set PATTY_EXE"}
    except subprocess.TimeoutExpired:
        return {"exit": 1, "items": [], "log": f"timed out after {timeout}s"}
    items = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    result = {"exit": done.returncode, "items": items}
    if done.stderr.strip():
        result["log"] = done.stderr.strip()
    return result


def _scan_flags(code_only: bool, data_only: bool, module: Optional[str], max_results: int) -> list[str]:
    flags = []
    if code_only:
        flags.append("-c")
    if data_only:
        flags.append("-d")
    if module:
        flags += ["-m", module]
    flags += ["-n", str(max_results)]
    return flags


@mcp.tool()
def ps(name_filter: str = "") -> dict:
    """List running processes, optionally only those whose name contains name_filter."""
    return _run(None, "ps", *([name_filter] if name_filter else []))


@mcp.tool()
def find(target: str, signature: str, code_only: bool = False, data_only: bool = False,
         module: Optional[str] = None, rip_offset: Optional[int] = None, max_results: int = 50) -> dict:
    """Search for a byte signature ("48 8B 05 ?? ?? ?? ??") or, if it is not hex, for text.
    rip_offset follows a rip-relative operand at that byte offset to the address it refers to."""
    flags = _scan_flags(code_only, data_only, module, max_results)
    if rip_offset is not None:
        flags += ["-r", str(rip_offset)]
    return _run(target, "find", *flags, signature)


@mcp.tool()
def findval(target: str, value: str, value_type: Optional[str] = None, data_only: bool = False,
            module: Optional[str] = None, max_results: int = 50) -> dict:
    """Search for a number. value_type: i8 i16 i32 i64 u8 u16 u32 u64 float double
    (default i32, or float when the value has a decimal point)."""
    flags = _scan_flags(False, data_only, module, max_results)
    return _run(target, "findval", *flags, value, *([value_type] if value_type else []))


@mcp.tool()
def refs(target: str, address: str, data_only: bool = False, max_results: int = 50) -> dict:
    """Find places that hold a pointer to address."""
    return _run(target, "refs", *_scan_flags(False, data_only, None, max_results), address)


@mcp.tool()
def read(target: str, value_type: str, address: str, count: int = 1) -> dict:
    """Read values: value_type is i8..u64, float, double, ptr or str."""
    return _run(target, "read", "-n", str(count), value_type, address)


@mcp.tool()
def probe(target: str, address: str, size: int = 0x100) -> dict:
    """Guess what each pointer-sized field of an object is (pointer, string, float, vtable...)."""
    return _run(target, "probe", "-s", str(size), address)


@mcp.tool()
def maps(target: str, name_filter: str = "") -> dict:
    """Readable memory regions, optionally filtered by name."""
    return _run(target, "maps", *([name_filter] if name_filter else []))


@mcp.tool()
def modules(target: str, name_filter: str = "") -> dict:
    """Loaded modules with base and size."""
    return _run(target, "modules", *([name_filter] if name_filter else []))


@mcp.tool()
def check(target: str, profile_path: str) -> dict:
    """Check a signature profile: ok (with the new RVA), ambiguous, missing or unresolved per signature."""
    return _run(target, "check", profile_path)


@mcp.tool()
def command(target: str, line: str) -> dict:
    """Run any patty shell command line, e.g. 'x/8xg [Game.exe+0x2A4F10]' or 'filter i32 == 90'."""
    return _run(target, *shlex.split(line))


if __name__ == "__main__":
    mcp.run()
