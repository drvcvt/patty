"""Patty MCP Server - Universal Memory Pattern Scanner."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional, Sequence

from fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("patty-mcp")

MAX_SCAN_RESULTS = 100000
MAX_SCAN_THREADS = 64
MAX_SCAN_CHUNK_SIZE = 64 * 1024 * 1024

SURFACE_HINTS = (
    "the following argument was not expected",
    "unknown option",
    "unrecognized option",
    "no such option",
    "subcommands:",
    "usage:",
    "required subcommand",
    "run with --help for more information",
)


def _find_patty_exe() -> str:
    if exe := os.environ.get("PATTY_EXE"):
        return exe
    candidates = [
        Path(__file__).parent.parent / "build_release" / "patty.exe",
        Path(__file__).parent.parent / "build" / "patty.exe",
        Path(__file__).parent.parent / "build_test" / "patty.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return "patty"


PATTY_EXE = _find_patty_exe()

mcp = FastMCP(
    "patty",
    instructions=(
        "Universal memory pattern scanner. Use these tools to scan live "
        "Windows processes or binary files for byte patterns, numeric values, "
        "pointers, and object layouts. Supports RIP-relative resolution, "
        "profile loading, and CLI-backed MCP automation."
    ),
)


def _json(payload: object) -> str:
    return json.dumps(payload, indent=2)


def _run_patty(args: Sequence[str], timeout: int = 120) -> dict:
    cmd = [PATTY_EXE, *args]
    logger.info("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout}s", "command": cmd}
    except FileNotFoundError:
        return {"error": f"Executable not found: {PATTY_EXE}", "command": cmd}

    payload = {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }
    if result.returncode == 2:
        payload["status"] = "no_matches"
    elif result.returncode != 0:
        payload["error"] = payload["stderr"] or f"Exit code {result.returncode}"
    return payload


def _run_patty_json(args: Sequence[str], timeout: int = 120) -> dict:
    result = _run_patty([*args, "--output", "json"], timeout)
    if "error" in result:
        return result
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {
            "error": "Failed to parse JSON",
            "raw": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "command": result.get("command", []),
            "returncode": result.get("returncode", 0),
        }


def _surface_mismatch(payload: dict) -> bool:
    haystack = "\n".join(
        str(payload.get(key, "")).lower() for key in ("error", "stderr", "raw") if payload.get(key)
    )
    return any(hint in haystack for hint in SURFACE_HINTS)


def _run_variants(variants: Sequence[tuple[list[str], Optional[str]]], timeout: int = 120) -> dict:
    fallbacks: list[dict] = []
    for index, (args, warning) in enumerate(variants):
        result = _run_patty_json(args, timeout)
        if "error" not in result:
            if fallbacks:
                result["_mcp_fallbacks"] = fallbacks
            if warning:
                result.setdefault("_mcp_warnings", []).append(warning)
            return result
        if index < len(variants) - 1 and _surface_mismatch(result):
            fallbacks.append(
                {
                    "command": args,
                    "error": result.get("error"),
                    "stderr": result.get("stderr"),
                    "raw": result.get("raw"),
                }
            )
            continue
        if fallbacks:
            result["_mcp_fallbacks"] = fallbacks
        return result
    return {"error": "No CLI variants configured"}


def _target_args(*, name: Optional[str] = None, pid: Optional[int] = None, file_path: Optional[str] = None):
    selectors = [bool(name), pid is not None, bool(file_path)]
    if sum(selectors) != 1:
        return None, {"error": "Specify exactly one of name, pid, or file_path"}
    if name:
        return ["--name", name], None
    if pid is not None:
        return ["--pid", str(pid)], None
    return ["--file", file_path or ""], None


def _scan_common_args(
    *,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: Optional[int] = None,
    resolve: Optional[str] = None,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
    thread_flag: str = "--threads",
) -> list[str]:
    max_results = _clamp_optional(max_results, field_name="max_results", maximum=MAX_SCAN_RESULTS)
    thread_count = _clamp_optional(thread_count, field_name="thread_count", maximum=MAX_SCAN_THREADS)
    chunk_size = _clamp_optional(chunk_size, field_name="chunk_size", maximum=MAX_SCAN_CHUNK_SIZE)

    args: list[str] = []
    if code_only:
        args.append("--code-only")
    if data_only:
        args.append("--data-only")
    if module:
        args.extend(["--module", module])
    if max_results is not None:
        args.extend(["--max", str(max_results)])
    if resolve:
        args.extend(["--resolve", resolve])
    if parallel:
        args.append("--parallel")
    if thread_count is not None:
        args.extend([thread_flag, str(thread_count)])
    if chunk_size is not None:
        args.extend(["--chunk-size", str(chunk_size)])
    return args


def _strip_tuning_args(args: Sequence[str]) -> list[str]:
    stripped: list[str] = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--parallel":
            continue
        if arg in {"--threads", "--thread-count", "--chunk-size"}:
            skip_next = True
            continue
        stripped.append(arg)
    return stripped


def _scan_cli(args: Sequence[str], timeout: int = 120) -> dict:
    variants: list[tuple[list[str], Optional[str]]] = [(list(args), None)]
    stripped = _strip_tuning_args(args)
    if stripped != list(args):
        variants.append(
            (
                stripped,
                "CLI does not support one or more tuning flags yet; ran without parallel/thread/chunk tuning.",
            )
        )
    return _run_variants(variants, timeout)


def _parse_int(value: int | str, field_name: str) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(value, 0)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name}: {value}") from exc


def _clamp_optional(value: Optional[int], *, field_name: str, maximum: int) -> Optional[int]:
    if value is None:
        return None
    if value < 0:
        raise ValueError(f"{field_name} must be >= 0")
    if value > maximum:
        logger.warning("Clamping %s from %s to %s", field_name, value, maximum)
        return maximum
    return value


def _encode_le_pattern(value: int, size: int) -> str:
    if size <= 0:
        raise ValueError("size must be positive")
    max_value = 1 << (size * 8)
    if value < 0 or value >= max_value:
        raise ValueError(f"Value {value} does not fit into {size} bytes")
    return " ".join(f"{byte:02X}" for byte in value.to_bytes(size, "little"))


def _run_profile_scan(
    target_args: Sequence[str],
    patterns: list[dict],
    *,
    timeout: int = 300,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 20,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> dict:
    profile = {"name": "mcp_multi_scan", "version": "1.0", "patterns": patterns}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, prefix="patty_", encoding="utf-8") as handle:
        json.dump(profile, handle)
        temp_path = handle.name
    try:
        args = [
            "scan",
            *target_args,
            "--profile",
            temp_path,
            *_scan_common_args(
                code_only=code_only,
                data_only=data_only,
                module=module,
                max_results=max_results,
                parallel=parallel,
                thread_count=thread_count,
                chunk_size=chunk_size,
            ),
        ]
        return _scan_cli(args, timeout)
    finally:
        Path(temp_path).unlink(missing_ok=True)


def _scan_value_compat(
    target_args: Sequence[str],
    *,
    value: int,
    size: int,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
    timeout: int = 120,
) -> dict:
    default_common = _scan_common_args(
        code_only=code_only,
        data_only=data_only,
        module=module,
        max_results=max_results,
        parallel=parallel,
        thread_count=thread_count,
        chunk_size=chunk_size,
    )
    alt_common = _scan_common_args(
        code_only=code_only,
        data_only=data_only,
        module=module,
        max_results=max_results,
        parallel=parallel,
        thread_count=thread_count,
        chunk_size=chunk_size,
        thread_flag="--thread-count",
    )
    pattern = _encode_le_pattern(value, size)
    variants: list[tuple[list[str], Optional[str]]] = [
        (["scan-value", *target_args, "--value", hex(value), "--size", str(size), *default_common], None),
        (["scan-value", *target_args, "--value", hex(value), "--value-size", str(size), *alt_common], None),
        (
            ["scan", *target_args, "--pattern", pattern, *default_common],
            "Dedicated scan-value CLI support is not available yet; used byte-pattern compatibility mode.",
        ),
    ]
    stripped = _strip_tuning_args(variants[-1][0])
    if stripped != variants[-1][0]:
        variants.append(
            (
                stripped,
                "Dedicated scan-value CLI support is not available yet; used byte-pattern compatibility mode without tuning flags.",
            )
        )
    return _run_variants(variants, timeout)


def _scan_pointer_compat(
    target_args: Sequence[str],
    *,
    target: int,
    pointer_size: int,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
    timeout: int = 120,
) -> dict:
    default_common = _scan_common_args(
        code_only=code_only,
        data_only=data_only,
        module=module,
        max_results=max_results,
        parallel=parallel,
        thread_count=thread_count,
        chunk_size=chunk_size,
    )
    alt_common = _scan_common_args(
        code_only=code_only,
        data_only=data_only,
        module=module,
        max_results=max_results,
        parallel=parallel,
        thread_count=thread_count,
        chunk_size=chunk_size,
        thread_flag="--thread-count",
    )
    pattern = _encode_le_pattern(target, pointer_size)
    variants: list[tuple[list[str], Optional[str]]] = []
    if pointer_size == 8:
        variants.extend(
            [
                (["scan-pointer", *target_args, "--address", hex(target), *default_common], None),
                (["scan-pointer", *target_args, "--address", hex(target), *alt_common], None),
            ]
        )
    variants.append(
        (
            ["scan", *target_args, "--pattern", pattern, *default_common],
            "Dedicated scan-pointer CLI support is not available yet; used byte-pattern compatibility mode.",
        )
    )
    stripped = _strip_tuning_args(variants[-1][0])
    if stripped != variants[-1][0]:
        variants.append(
            (
                stripped,
                "Dedicated scan-pointer CLI support is not available yet; used byte-pattern compatibility mode without tuning flags.",
            )
        )
    return _run_variants(variants, timeout)


def _pointer_patterns(targets: Iterable[int], pointer_size: int) -> list[dict]:
    return [{"name": f"ptr_{index}", "aob": _encode_le_pattern(target, pointer_size)} for index, target in enumerate(targets)]


@mcp.tool()
def scan_process(
    name: str,
    pattern: str,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    resolve: Optional[str] = None,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a live Windows process for a byte pattern (AOB signature)."""
    args = [
        "scan",
        "--name",
        name,
        "--pattern",
        pattern,
        *_scan_common_args(
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            resolve=resolve,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        ),
    ]
    return _json(_scan_cli(args))


@mcp.tool()
def scan_process_by_pid(
    pid: int,
    pattern: str,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    resolve: Optional[str] = None,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a live process by PID for a byte pattern."""
    args = [
        "scan",
        "--pid",
        str(pid),
        "--pattern",
        pattern,
        *_scan_common_args(
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            resolve=resolve,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        ),
    ]
    return _json(_scan_cli(args))


@mcp.tool()
def scan_file(
    path: str,
    pattern: str,
    code_only: bool = False,
    data_only: bool = False,
    max_results: int = 50,
    resolve: Optional[str] = None,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a binary file (PE/ELF/raw) for a byte pattern."""
    args = [
        "scan",
        "--file",
        path,
        "--pattern",
        pattern,
        *_scan_common_args(
            code_only=code_only,
            data_only=data_only,
            max_results=max_results,
            resolve=resolve,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        ),
    ]
    return _json(_scan_cli(args))


@mcp.tool()
def scan_with_profile(
    profile_path: str,
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a target using a JSON target profile containing multiple patterns."""
    target_args, error = _target_args(name=name, pid=pid, file_path=file_path)
    if error:
        return _json(error)
    args = [
        "scan",
        *target_args,
        "--profile",
        profile_path,
        *_scan_common_args(
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        ),
    ]
    return _json(_scan_cli(args))


@mcp.tool()
def list_regions(
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
) -> str:
    """List memory regions of a process or binary file."""
    target_args, error = _target_args(name=name, pid=pid, file_path=file_path)
    if error:
        return _json(error)
    result = _run_patty_json(["list", *target_args])
    if isinstance(result, dict) and isinstance(result.get("regions"), list):
        # Preserve the legacy MCP response shape even though the CLI now emits a versioned envelope.
        return _json(result["regions"])
    return _json(result)


@mcp.tool()
def dump_memory(
    region: str,
    size: int,
    output: str = "dump.bin",
    name: Optional[str] = None,
    pid: Optional[int] = None,
) -> str:
    """Dump a memory region from a live process to a file."""
    if bool(name) == (pid is not None):
        return _json({"error": "Specify exactly one of name or pid"})
    args = ["dump", "--region", region, "--size", str(size), "--output", output]
    args.extend(["--name", name] if name else ["--pid", str(pid)])
    result = _run_patty(args)
    if "error" in result:
        return _json(result)
    return _json({"status": "ok", "output": output, "message": result["stdout"]})


@mcp.tool()
def multi_scan_process(
    name: str,
    patterns: list[dict],
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 20,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a process for multiple patterns at once using a temporary profile."""
    return _json(
        _run_profile_scan(
            ["--name", name],
            patterns,
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        )
    )


@mcp.tool()
def multi_scan_file(
    path: str,
    patterns: list[dict],
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 20,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a file for multiple patterns at once using a temporary profile."""
    return _json(
        _run_profile_scan(
            ["--file", path],
            patterns,
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        )
    )


@mcp.tool()
def find_string_references(
    target: str,
    search_string: str,
    is_file: bool = False,
    max_results: int = 20,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Find occurrences of an ASCII string in a process or file."""
    pattern = " ".join(f"{byte:02X}" for byte in search_string.encode("ascii", errors="replace"))
    target_args = ["--file", target] if is_file else ["--name", target]
    common_args = _scan_common_args(
        code_only=code_only,
        data_only=data_only,
        module=module,
        max_results=max_results,
        parallel=parallel,
        thread_count=thread_count,
        chunk_size=chunk_size,
    )
    return _json(
        _run_variants(
            [
                (["scan", *target_args, "--string", search_string, *common_args], None),
                (
                    ["scan", *target_args, "--pattern", pattern, *common_args],
                    "CLI string-pattern support is not available yet; used byte-pattern compatibility mode.",
                ),
            ]
        )
    )


@mcp.tool()
def scan_value(
    value: int | str,
    value_size: int = 8,
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a target for an exact numeric value."""
    if value_size <= 0 or value_size > 8:
        return _json({"error": "value_size must be between 1 and 8"})
    target_args, error = _target_args(name=name, pid=pid, file_path=file_path)
    if error:
        return _json(error)
    try:
        parsed_value = _parse_int(value, "value")
        result = _scan_value_compat(
            target_args,
            value=parsed_value,
            size=value_size,
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        )
    except ValueError as exc:
        return _json({"error": str(exc)})
    return _json(result)


@mcp.tool()
def scan_pointer(
    target: int | str,
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
    pointer_size: int = 8,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 50,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a target for a single pointer value."""
    if pointer_size not in {4, 8}:
        return _json({"error": "pointer_size must be 4 or 8"})
    target_args, error = _target_args(name=name, pid=pid, file_path=file_path)
    if error:
        return _json(error)
    try:
        parsed_target = _parse_int(target, "target")
        result = _scan_pointer_compat(
            target_args,
            target=parsed_target,
            pointer_size=pointer_size,
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        )
    except ValueError as exc:
        return _json({"error": str(exc)})
    return _json(result)


@mcp.tool()
def scan_pointers(
    targets: list[int | str],
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
    pointer_size: int = 8,
    code_only: bool = False,
    data_only: bool = False,
    module: Optional[str] = None,
    max_results: int = 20,
    parallel: bool = False,
    thread_count: Optional[int] = None,
    chunk_size: Optional[int] = None,
) -> str:
    """Scan a target for multiple pointer values at once."""
    if pointer_size not in {4, 8}:
        return _json({"error": "pointer_size must be 4 or 8"})
    if not targets:
        return _json({"error": "Provide at least one pointer target"})
    target_args, error = _target_args(name=name, pid=pid, file_path=file_path)
    if error:
        return _json(error)
    try:
        parsed_targets = [_parse_int(target, "target") for target in targets]
        direct_variants: list[tuple[list[str], Optional[str]]] = []
        if pointer_size == 8:
            direct_variants.extend(
                [
                    (
                        [
                            "scan-pointers",
                            *target_args,
                            *sum((["--address", hex(target)] for target in parsed_targets), []),
                            *_scan_common_args(
                                code_only=code_only,
                                data_only=data_only,
                                module=module,
                                max_results=max_results,
                                parallel=parallel,
                                thread_count=thread_count,
                                chunk_size=chunk_size,
                            ),
                        ],
                        None,
                    ),
                    (
                        [
                            "scan-pointers",
                            *target_args,
                            *sum((["--address", hex(target)] for target in parsed_targets), []),
                            *_scan_common_args(
                                code_only=code_only,
                                data_only=data_only,
                                module=module,
                                max_results=max_results,
                                parallel=parallel,
                                thread_count=thread_count,
                                chunk_size=chunk_size,
                                thread_flag="--thread-count",
                            ),
                        ],
                        None,
                    ),
                ]
            )
        direct_result = _run_variants(direct_variants, timeout=300) if direct_variants else {
            "error": "No dedicated scan-pointers CLI variant for this pointer size"
        }
        if direct_variants and "error" not in direct_result:
            return _json(direct_result)
        if direct_variants and not (_surface_mismatch(direct_result) or direct_result.get("_mcp_fallbacks")):
            return _json(direct_result)
        result = _run_profile_scan(
            target_args,
            _pointer_patterns(parsed_targets, pointer_size),
            timeout=300,
            code_only=code_only,
            data_only=data_only,
            module=module,
            max_results=max_results,
            parallel=parallel,
            thread_count=thread_count,
            chunk_size=chunk_size,
        )
        if direct_result.get("_mcp_fallbacks"):
            result["_mcp_fallbacks"] = direct_result["_mcp_fallbacks"]
        result.setdefault("_mcp_warnings", []).append(
            "Dedicated scan-pointers CLI support is not available yet; used profile-based compatibility mode."
        )
    except ValueError as exc:
        return _json({"error": str(exc)})
    return _json(result)


@mcp.tool()
def probe_object(
    address: int | str,
    name: Optional[str] = None,
    pid: Optional[int] = None,
    file_path: Optional[str] = None,
    max_size: int = 0x400,
) -> str:
    """Probe an object's memory layout and classify pointer-sized fields."""
    target_args, error = _target_args(name=name, pid=pid, file_path=file_path)
    if error:
        return _json(error)
    try:
        parsed_address = _parse_int(address, "address")
    except ValueError as exc:
        return _json({"error": str(exc)})
    result = _run_variants(
        [
            (["probe", *target_args, "--address", hex(parsed_address), "--size", str(max_size)], None),
            (["probe", *target_args, "--address", hex(parsed_address), "--max-size", str(max_size)], None),
        ],
        timeout=120,
    )
    if "error" in result and _surface_mismatch(result):
        result.setdefault("_mcp_warnings", []).append(
            "Probe support requires the upcoming CLI `probe` subcommand; current CLI surface cannot emulate this safely."
        )
    return _json(result)


if __name__ == "__main__":
    mcp.run()
