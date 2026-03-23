"""Patty MCP Server — Universal Memory Pattern Scanner."""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional

from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("patty-mcp")

# Resolve patty executable: env var > sibling build dir > PATH
def _find_patty_exe() -> str:
    if exe := os.environ.get("PATTY_EXE"):
        return exe
    candidates = [
        Path(__file__).parent.parent / "build_release" / "patty.exe",
        Path(__file__).parent.parent / "build" / "patty.exe",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return "patty"

PATTY_EXE = _find_patty_exe()

mcp = FastMCP(
    "patty",
    instructions=(
        "Universal memory pattern scanner. Use these tools to scan live "
        "Windows processes or binary files for byte patterns (AOB signatures). "
        "Supports RIP-relative resolution, pointer chain following, "
        "PE/ELF section parsing, and target profile loading."
    ),
)


def _run_patty(args: list[str], timeout: int = 120) -> dict:
    cmd = [PATTY_EXE] + args
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s"}
    except FileNotFoundError:
        return {"error": f"Executable not found: {PATTY_EXE}"}
    if result.returncode != 0:
        stderr = result.stderr.strip()
        return {"error": stderr or f"Exit code {result.returncode}"}
    return {"stdout": result.stdout.strip(), "stderr": result.stderr.strip()}


def _run_patty_json(args: list[str], timeout: int = 120) -> dict:
    result = _run_patty(args + ["--output", "json"], timeout)
    if "error" in result:
        return result
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON", "raw": result["stdout"]}


@mcp.tool()
def scan_process(
    name: str,
    pattern: str,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    resolve: Optional[str] = None,
) -> str:
    """Scan a live Windows process for a byte pattern (AOB signature).

    Args:
        name: Process name (e.g. 'game.exe')
        pattern: AOB pattern with ?? wildcards (e.g. '48 8B 05 ?? ?? ?? ??')
        code_only: Only scan executable memory regions
        data_only: Only scan writable data regions
        module: Filter scan to a specific loaded module
        max_results: Maximum number of results (default 50)
        resolve: Post-match resolution: 'rip' for RIP-relative, 'deref' for dereference
    """
    args = ["scan", "--name", name, "--pattern", pattern, "--max", str(max_results)]
    if code_only: args.append("--code-only")
    if data_only: args.append("--data-only")
    if module: args.extend(["--module", module])
    if resolve: args.extend(["--resolve", resolve])
    return json.dumps(_run_patty_json(args), indent=2)


@mcp.tool()
def scan_process_by_pid(
    pid: int,
    pattern: str,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    resolve: Optional[str] = None,
) -> str:
    """Scan a live process by PID for a byte pattern.

    Args:
        pid: Process ID
        pattern: AOB pattern with ?? wildcards
        code_only: Only scan executable memory regions
        data_only: Only scan writable data regions
        module: Filter scan to a specific loaded module
        max_results: Maximum number of results (default 50)
        resolve: Post-match resolution: 'rip' or 'deref'
    """
    args = ["scan", "--pid", str(pid), "--pattern", pattern, "--max", str(max_results)]
    if code_only: args.append("--code-only")
    if data_only: args.append("--data-only")
    if module: args.extend(["--module", module])
    if resolve: args.extend(["--resolve", resolve])
    return json.dumps(_run_patty_json(args), indent=2)


@mcp.tool()
def scan_file(
    path: str,
    pattern: str,
    code_only: bool = False,
    data_only: bool = False,
    max_results: int = 50,
    resolve: Optional[str] = None,
) -> str:
    """Scan a binary file (PE/ELF/raw) for a byte pattern.

    Args:
        path: Path to the file to scan
        pattern: AOB pattern with ?? wildcards
        code_only: Only scan executable sections
        data_only: Only scan data sections
        max_results: Maximum number of results (default 50)
        resolve: Post-match resolution: 'rip' or 'deref'
    """
    args = ["scan", "--file", path, "--pattern", pattern, "--max", str(max_results)]
    if code_only: args.append("--code-only")
    if data_only: args.append("--data-only")
    if resolve: args.extend(["--resolve", resolve])
    return json.dumps(_run_patty_json(args), indent=2)


@mcp.tool()
def scan_with_profile(
    profile_path: str,
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
    code_only: bool = False,
    max_results: int = 50,
) -> str:
    """Scan a target using a JSON target profile containing multiple patterns.

    Args:
        profile_path: Path to the JSON profile file
        name: Process name (mutually exclusive with pid/file_path)
        pid: Process ID (mutually exclusive with name/file_path)
        file_path: File path (mutually exclusive with name/pid)
        code_only: Only scan executable regions
        max_results: Maximum results per pattern (default 50)
    """
    args = ["scan", "--profile", profile_path, "--max", str(max_results)]
    if name: args.extend(["--name", name])
    elif pid is not None: args.extend(["--pid", str(pid)])
    elif file_path: args.extend(["--file", file_path])
    else: return json.dumps({"error": "Specify name, pid, or file_path"})
    if code_only: args.append("--code-only")
    return json.dumps(_run_patty_json(args), indent=2)


@mcp.tool()
def list_regions(
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
) -> str:
    """List memory regions of a process or binary file.

    Args:
        name: Process name
        pid: Process ID
        file_path: Path to binary file
    """
    args = ["list"]
    if name: args.extend(["--name", name])
    elif pid is not None: args.extend(["--pid", str(pid)])
    elif file_path: args.extend(["--file", file_path])
    else: return json.dumps({"error": "Specify name, pid, or file_path"})
    return json.dumps(_run_patty_json(args), indent=2)


@mcp.tool()
def dump_memory(
    region: str,
    size: int,
    output: str = "dump.bin",
    name: Optional[str] = None,
    pid: Optional[int] = None,
) -> str:
    """Dump a memory region from a live process to a file.

    Args:
        region: Base address of the region in hex (e.g. '7FF6A0010000')
        size: Number of bytes to dump
        output: Output file path (default: dump.bin)
        name: Process name
        pid: Process ID
    """
    args = ["dump", "--region", region, "--size", str(size), "--output", output]
    if name: args.extend(["--name", name])
    elif pid is not None: args.extend(["--pid", str(pid)])
    else: return json.dumps({"error": "Specify name or pid"})
    result = _run_patty(args)
    if "error" in result: return json.dumps(result)
    return json.dumps({"status": "ok", "output": output, "message": result["stdout"]})


@mcp.tool()
def multi_scan_process(
    name: str,
    patterns: list[dict],
    code_only: bool = False,
    max_results: int = 20,
) -> str:
    """Scan a process for multiple patterns at once using a temporary profile.

    Args:
        name: Process name (e.g. 'game.exe')
        patterns: List of pattern dicts with keys: name, aob, result_offset (opt), resolve (opt)
        code_only: Only scan executable regions
        max_results: Max results per pattern (default 20)
    """
    import tempfile
    profile = {"name": "multi_scan", "version": "1.0", "patterns": patterns}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="patty_") as f:
        json.dump(profile, f)
        tmp_path = f.name
    try:
        args = ["scan", "--name", name, "--profile", tmp_path, "--max", str(max_results)]
        if code_only: args.append("--code-only")
        return json.dumps(_run_patty_json(args, timeout=300), indent=2)
    finally:
        os.unlink(tmp_path)


@mcp.tool()
def multi_scan_file(
    path: str,
    patterns: list[dict],
    code_only: bool = False,
    max_results: int = 20,
) -> str:
    """Scan a file for multiple patterns at once using a temporary profile.

    Args:
        path: Path to binary file
        patterns: List of pattern dicts with keys: name, aob, result_offset (opt), resolve (opt)
        code_only: Only scan executable sections
        max_results: Max results per pattern (default 20)
    """
    import tempfile
    profile = {"name": "multi_scan", "version": "1.0", "patterns": patterns}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="patty_") as f:
        json.dump(profile, f)
        tmp_path = f.name
    try:
        args = ["scan", "--file", path, "--profile", tmp_path, "--max", str(max_results)]
        if code_only: args.append("--code-only")
        return json.dumps(_run_patty_json(args, timeout=300), indent=2)
    finally:
        os.unlink(tmp_path)


@mcp.tool()
def find_string_references(
    target: str,
    search_string: str,
    is_file: bool = False,
    max_results: int = 20,
) -> str:
    """Find occurrences of an ASCII string in a process or file.

    Args:
        target: Process name or file path
        search_string: ASCII string to search for
        is_file: True if target is a file path, False if process name
        max_results: Maximum results (default 20)
    """
    hex_pattern = " ".join(f"{b:02X}" for b in search_string.encode("ascii", errors="replace"))
    args = ["scan"]
    if is_file: args.extend(["--file", target])
    else: args.extend(["--name", target])
    args.extend(["--pattern", hex_pattern, "--max", str(max_results)])
    return json.dumps(_run_patty_json(args), indent=2)


if __name__ == "__main__":
    mcp.run()
