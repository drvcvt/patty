# patty

Read-only memory scanner for live processes and binaries on disk.

Give it a byte signature and it finds the code, follows the `rip`-relative
operand to the global behind it, and after the next game update tells you
which of your signatures still hold.

| | |
|---|---|
| `patty` | interactive shell, gdb flavoured |
| `patty scan …`, `patty check …` | one-shot commands, JSON output for scripts |
| `#include <patty/patty.h>` | the C++20 library both are built on |

```text
patty toygame:1794414> find -c -m toygame -o 3 -r rip 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.7 ms

1 match
  $1    0x0000563F641D91ED -> 0x0000563F641DC020  toygame
patty toygame:1794414> probe -s 0x18 [$1]
Probed 24 B at 0x0000563F80578030

  +0     0x0000000C42AF0000  float       87.500000
  +8     0x0000563F641DA00A  string_ptr  PlayerOne
  +10    0x0000563F80578010  pointer     -> 0x563F80578010
```

Linux and Windows. On Linux patty reads memory with `process_vm_readv` and
nothing else: it never attaches, never stops the target and never opens
`/proc/<pid>/mem`.

---

- [Setup](#setup)
- [The shell](#the-shell)
- [One-shot commands](#one-shot-commands)
- [Profiles and `check`](#profiles-and-check)
- [Using patty as a library](#using-patty-as-a-library)
- [MCP server](#mcp-server)
- [Building by hand](#building-by-hand)
- [Speed](#speed)
- [Limits](#limits)

## Setup

```bash
git clone https://github.com/drvcvt/patty.git
cd patty
scripts/setup.sh
```

The script asks for your sudo password **once, right at the start**, and then
runs without further prompts:

1. creates `mcp/.venv` with `fastmcp` for the MCP server
2. builds into `build/` and runs the test suite
3. installs binary, headers and CMake package to `~/.local`
4. runs `sudo setcap cap_sys_ptrace=ep` on `~/.local/bin/patty` and `build/patty`

| Flag | |
|---|---|
| `--prefix DIR` | install somewhere else than `~/.local` |
| `--no-setcap` | skip step 4, the script never calls sudo |
| `--no-mcp` | skip the Python venv |
| `--jobs N` | parallel build jobs, default 4 |

Needs CMake 3.20+, Ninja, a C++20 compiler, Python 3 and `setcap` (libcap).
Missing libraries (nlohmann/json, CLI11, GoogleTest, isocline) are fetched by CMake.

### Why sudo

Most distributions ship `kernel.yama.ptrace_scope = 1`, which means a process
may only read the memory of its own children. patty does not use ptrace, but
the kernel guards `process_vm_readv` with the same permission check. Giving the
binary `cap_sys_ptrace` lifts the restriction for patty alone, so you neither
run it as root nor loosen the setting for the whole system.

Two consequences worth knowing:

- With the capability, patty can read **any** process, root's included. The
  script makes the binary `chmod 700` so other users on the machine cannot use
  it that way.
- Rebuilding replaces the file and the capability is gone. Run the script
  again after a rebuild.

Without the capability you get a clear error instead of empty results:

```text
patty: not allowed to read pid 979010 (kernel.yama.ptrace_scope=1). patty only uses
process_vm_readv, but the kernel gates it like ptrace. Run scripts/setup.sh once, or:
sudo setcap cap_sys_ptrace=ep $(command -v patty)
```

On Windows none of this applies; patty opens the process with
`PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`.

## The shell

Start it with `patty`, or open a target right away with
`patty repl --name Game.exe`, `--pid 4242` or `--file Game.exe`.

To try it without a game, `examples/toygame.c` is a 40 line program with a
global `Player*`. It allows reading by any process of yours, so it works even
before `setup.sh`:

```bash
gcc -O1 -o toygame examples/toygame.c && ./toygame &
patty repl --name toygame
```

This session is real output from that program:

```text
patty> proc toygame
opened pid 1794414 (toygame)
patty toygame:1794414> find -c -m toygame -o 3 -r rip 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.7 ms

1 match
  $1    0x0000563F641D91ED -> 0x0000563F641DC020  toygame
patty toygame:1794414> p $1
$2 = 0x0000563F641DC020  toygame+0x4020 rw-
patty toygame:1794414> x/a $1
0x0000563F641DC020  0x0000563F80578030  rw- [heap]
patty toygame:1794414> x/s [[$1]+8]
0x0000563F641DA00A  "PlayerOne"
patty toygame:1794414> p [[$1]+0x10]
$3 = 0x0000563F80578010  rw- [heap]
patty toygame:1794414> x/fw $
0x0000563F80578010  40
```

The signature sits in `tick()`, `-o 3 -r rip` turns the `mov rax, [rip+disp]`
into the address of `g_local`, and `toygame+0x4020` is the same offset objdump
prints for it. From there it is pointer walking: `[$1]` is the player,
`+8` its name, `+0x10` the enemy it targets, whose health is 40.

<details>
<summary><b>All shell commands</b></summary>

| Command | Does |
|---|---|
| `proc <pid\|name>` | open a running process |
| `file [-raw] <path>` | open a PE, ELF or raw dump |
| `info`, `maps [text]`, `modules [text]` | what is loaded where |
| `find [flags] <aob \| "text">` | pattern or string search, `-c` code, `-d` data, `-m` module, `-n` max, `-o`/`-r` resolve, `-s` MSVC string object |
| `findval <value> [type]` | `i8`..`u64`, `float`, `double`; `87.5` defaults to float |
| `refs <expr>` | pointers to an address |
| `x[/NFU] <expr>` | examine memory, gdb style: formats `x d u f a s c`, units `b h w g` |
| `p <expr>` | evaluate an address and say where it points |
| `probe [-s size] <expr>` | guess what each field of an object is |
| `load <profile>`, `check` | run a signature profile against the target |
| `dump <file> <size> <expr>` | save memory to a file |
| `set max N`, `set parallel on` | scan defaults (max 50, parallel on) |

`help <command>` has details and examples for each.

</details>

**Expressions** work wherever an address is expected: numbers (`0x` for hex,
like gdb), module names (`Game.exe+0x2A4F10`, quote names with a dash:
`'ld-linux-x86-64.so.2'`), `$` for the last value and `$N` for any earlier one,
`[expr]` to read a pointer, and `+ - * /` with parentheses.

Tab completes commands, module names and paths. History is kept in
`~/.local/state/patty/history`. Ctrl-C stops a running scan, Ctrl-D twice
leaves. Piped input runs as a script: `patty repl --name Game.exe < steps.txt`.

## One-shot commands

```bash
patty scan --name Game.exe --module Game.exe --code-only \
           --pattern "48 8B 05 ?? ?? ?? ?? 48 85 C0" --offset 3 --resolve rip
patty scan --file Game.exe --string "PlayerController"
patty scan-value   --name Game.exe --value 1337 --size 4 --data-only
patty scan-pointer --name Game.exe --address 0x7FF6A0010000
patty probe --name Game.exe --address 0x1D2E4C80
patty list  --name Game.exe --modules
patty dump  --name Game.exe --address 0x7FF6A0010000 --size 0x1000 -o text.bin
```

All scan commands take `--code-only`, `--data-only`, `--module`, `--region`
(a section name such as `.text` for files), `--max` and `--threads`. Scans use
all cores by default; `--threads 1` keeps them on one.
`-o json` prints machine readable output with `"schema_version": 2`.

Exit codes: `0` found something, `2` found nothing (or `check` was not all ok),
`1` error.

Files are laid out the way the loader maps them, with every section at its
virtual address. An address from `--file Game.exe` is the one IDA shows, and
RVAs from a file and from the running process agree.

## Profiles and `check`

A profile is a JSON list of signatures you keep next to your offsets:

```json
{
  "name": "toygame",
  "module": "toygame",
  "patterns": [
    { "name": "LocalPlayer", "aob": "48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0",
      "result_offset": 3, "resolve": ["rip"] },
    { "name": "Tick", "aob": "F3 0F 1E FA 48 8B 05" },
    { "name": "Prologue", "aob": "F3 0F 1E FA" },
    { "name": "SpawnEnemy", "aob": "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 C3" }
  ]
}
```

Pattern keys: `aob` (or `ida`), `string`, `sso_string` (MSVC `std::string`),
plus optional `result_offset` and `resolve` (`"rip"`, `"deref"`,
`{"type": "add", "extra": 8}`).

After an update, `check` tells you which ones survived. Against the binary on
disk and against the running process, from `examples/toygame.json`:

```console
$ patty check --file toygame --profile examples/toygame.json
Checked 4 pattern(s) over 2.8 KB in 1.4 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x0000000000004020  rva 0x00004020
  ok          Tick         0x00000000000011E9  rva 0x000011E9
  ambiguous   Prologue     20 matches
  missing     SpawnEnemy

$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 3.5 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x000055A3191A1020  rva 0x00004020
  ok          Tick         0x000055A31919E1E9  rva 0x000011E9
  ambiguous   Prologue     20 matches
  missing     SpawnEnemy
```

| Status | Meaning |
|---|---|
| `ok` | exactly one match, or several that resolve to the same address |
| `ambiguous` | several matches pointing to different places |
| `missing` | nothing matched, the signature needs work |
| `unresolved` | matched, but following it failed (e.g. a global that is still null) |

For processes the profile's `module` limits the scan and the RVA base. For
files the whole image is scanned and RVAs are relative to its image base.
`check` exits with `2` unless everything is `ok`, which makes it easy to put
into a script that runs after every patch.

## Using patty as a library

After `setup.sh`, point CMake at the install prefix:

```cmake
find_package(patty CONFIG REQUIRED)   # cmake -DCMAKE_PREFIX_PATH=~/.local
target_link_libraries(my_tool PRIVATE patty::patty)
```

```cpp
#include <patty/patty.h>
#include <cstdio>

int main() {
    try {
        auto game = patty::Process::open("toygame");
        patty::Scanner scan{game};

        // mov rax, [rip+g_local] ; pxor xmm0, xmm0 ; test rax, rax
        auto local = patty::Pattern::aob("48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0").rip(3);
        auto hits = scan.find(local, {.module = "toygame", .code_only = true});
        if (hits.size() != 1) {
            std::puts("signature broke, time to update it");
            return 1;
        }

        uintptr_t player = game.read_pointer(hits[0].value()).value_or(0);
        float health = game.read<float>(player).value_or(0);
        auto name = game.read_string(game.read_pointer(player + 0x8).value_or(0));
        std::printf("%s has %.1f hp\n", name.value_or("?").c_str(), health);

        // Same walk as a pointer chain: [[global] + 0x10] is the target, +0 its health.
        if (auto enemy = patty::pointer_chain(game, hits[0].value(), {0, 0x10, 0}))
            std::printf("target has %.1f hp\n", game.read<float>(*enemy).value_or(0));
    } catch (const patty::Error& e) {
        std::fprintf(stderr, "patty: %s\n", e.what());
        return 1;
    }
}
```

```text
PlayerOne has 87.5 hp
target has 40.0 hp
```

<details>
<summary><b>The pieces</b></summary>

| Type | |
|---|---|
| `Process` | `open(pid)`, `open("Game.exe")`, `current()`, `find(name)` |
| `Image` | `open(path)` maps PE/ELF like a loader, `open_raw(path, base)`, `from_bytes(bytes, base)` |
| `Target` | what both share: `read<T>`, `read_pointer`, `read_string`, `read_bytes`, `view` (zero-copy), `regions`, `modules`, `module(name)`, `region_at` |
| `Pattern` | `aob`, `text`, `raw(bytes, mask)`, `integer(v, size)`, `value(x)`, `msvc_string`; chain `.rip(n)`, `.deref()`, `.add(n)`, `.named(s)` |
| `Scanner` | `find(pattern)` or `find(patterns)` in one pass, `find_pointer(s)`, `probe`, `check(profile)` |
| `ScanOptions` | `module`, `code_only`, `data_only`, `max`, `parallel`, `threads`, `filter`, `cancel` |
| `Profile` | `load(path)`, `parse(json)` |
| `pointer_chain`, `rip_relative`, `resolve` | the resolve steps as free functions |

</details>

A few rules the API sticks to:

- Opening a target, parsing a pattern or profile, and scanning a module that is
  not loaded throw `patty::Error` with a message that says what went wrong.
- Reads never throw. They return `bool`, `std::optional` or an empty vector.
- `Scanner` borrows the target. Keep the target alive while you scan.
- Matches come back sorted by address. `Match::resolved` is only set when the
  pattern has resolve steps, and `Match::value()` gives you whichever applies.
- Scans use all cores unless `ScanOptions::parallel` is false or `threads` is 1.
- `ScanOptions::cancel` takes a `std::atomic_bool*`, checked once per chunk.
- To scan something else (a dump format, remote memory, a DMA device),
  derive from `Target` and implement `read`, `regions` and `describe`. If the
  bytes already sit in your process, also implement `view` and the scanner
  reads them in place.

## MCP server

`mcp/server.py` exposes the CLI to Claude Code and other MCP clients:
`scan_process`, `scan_file`, `scan_value`, `scan_pointer`, `probe_object`,
`list_regions`, `check_profile` and a few more. `setup.sh` creates its venv.

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

Point `PATTY_EXE` at the binary that has the capability.

## Building by hand

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
cmake --install build --prefix ~/.local
```

| Option | Default | |
|---|---|---|
| `BUILD_SHARED_LIBS` | `OFF` | build `libpatty` shared instead of static |
| `PATTY_BUILD_CLI` | `ON` | the `patty` executable and the shell |
| `PATTY_BUILD_TESTS` | `ON` | GoogleTest suite and smoke tests |

```text
include/patty/    public headers: memory/ (targets), scan/ (patterns, scanner), profile/
src/              the library
cli/              command line tool, cli/repl/ is the shell
mcp/              MCP server
examples/         toygame.c and its profile
scripts/setup.sh  build, test, install, setcap
```

## Speed

i5-12400F (6 cores, 12 threads, AVX2), release build, best of five runs on a
machine that was busy with other work at the time:

| | one thread | all cores (default) |
|---|---|---|
| 154 MiB binary (libLLVM), one signature | 11 to 12 ms | 4.4 to 5 ms |
| same binary, profile with 20 signatures | 98 ms | 16 ms |
| 1 GiB of a live process, one signature | 163 ms | 41 ms |
| same process, 20 signatures | 750 ms | 115 ms |
| opening that 154 MiB binary | 2 ms | |

Where it comes from:

- For every signature patty picks the two fixed bytes that are rarest in real
  x86-64 binaries and compares both for 64 positions at a time with AVX2
  (SSE2 or plain `memchr` where AVX2 is missing). Only positions where both
  agree get the full comparison, so a signature starting with `48` or `00` is
  as fast as any other: around 20 GB/s per core, which is what one core can
  pull from memory.
- Binaries on disk are memory-mapped and scanned in place, nothing is copied.
- Live memory is copied with `process_vm_readv` in 256 KiB pieces on all
  cores, small enough to stay in each core's L2 cache. On a single core about
  two thirds of the time is the kernel copying memory, which is why the
  default spreads the work.
- Several signatures are scanned in one pass over memory: each piece is
  checked against all of them while it is still in cache.

## Limits

- Read-only. No writing, freezing, breakpoints or disassembly.
- 32-bit Windows games under new-style (WoW64) Wine are reported as 64-bit.
- The Windows build compiles (checked with MinGW) but this version has not
  been run on a Windows machine yet.
- No macOS.
- The API may still change before 1.0.

## License

Non-commercial, see [LICENSE](LICENSE).
