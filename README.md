# patty

Sig scanner for live processes and PE/ELF files, Linux and Windows. CLI, a
gdb-ish shell and a C++20 library.

Read-only. On Linux it only uses `process_vm_readv`: no ptrace attach, nothing
gets stopped, no `/proc/<pid>/mem`.

```text
patty toygame:2029764> find -c -m toygame -o 3 -r rip 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.2 ms

1 match
  $6    0x000055BAD5B451ED -> 0x000055BAD5B48020  toygame
patty toygame:2029764> x/s [[$6]+8]
0x000055BAD5B4600A  "PlayerOne"
patty toygame:2029764> p [[$6]+0x10]
$7 = 0x000055BB1243E010  rw- [heap]
patty toygame:2029764> x/fw $
0x000055BB1243E010  40
```

## Install

```bash
git clone https://github.com/drvcvt/patty.git && cd patty
scripts/setup.sh
```

Builds, runs the tests, installs to `~/.local` and setcaps the binary. Asks for
sudo once at the start, then runs through.

Flags: `--prefix DIR`, `--no-setcap` (no sudo at all), `--mcp` (optional MCP
server, see [mcp/README.md](mcp/README.md)), `--jobs N`.

Needs CMake 3.20+, Ninja and a C++20 compiler. nlohmann/json, CLI11,
GoogleTest and isocline get fetched if you don't have them.

**Why sudo:** with `kernel.yama.ptrace_scope=1` (default on most distros) the
kernel blocks `process_vm_readv` on anything that isn't your own child process,
even though it's not ptrace. `cap_sys_ptrace` on the binary fixes that for
patty only. With that cap patty can read root's processes too, so the script
also does `chmod 700` on it. A rebuild drops the cap, rerun the script after.

If the cap is missing you get an error that says so, not empty results.

## Tutorial

[TUTORIAL.md](TUTORIAL.md): find a value in a toy program, trace it back to a
global, make a sig out of it, then break it with an "update". About 10 minutes,
no game or sudo needed.

## Shell

```bash
patty                        # then: proc Game.exe / file Game.exe
patty repl --name Game.exe   # or --pid / --file
```

Results get numbered like in gdb: `$1`, `$2`, `$` is the last one.
Expressions work anywhere an address goes: `Game.exe+0x2A4F10`, `[$1]+0x18`
(brackets read a pointer), `0x` for hex, quotes around module names with a
dash (`'ld-linux-x86-64.so.2'`).

<details>
<summary>commands</summary>

| | |
|---|---|
| `proc <pid\|name>` | open a process |
| `file [-raw] <path>` | open a PE, ELF or raw dump |
| `info`, `maps [text]`, `modules [text]` | what's loaded where |
| `find [-c] [-d] [-m mod] [-n max] [-o n] [-r rip,deref,add:8] <aob \| "text">` | sig or string search |
| `findval <value> [i8..u64\|float\|double]` | number search |
| `refs <expr>` | pointers to an address |
| `x[/NFU] <expr>` | examine memory like gdb (`x d u f a s c`, `b h w g`) |
| `p <expr>` | evaluate, show where it points |
| `probe [-s size] <expr>` | guess field types of an object |
| `load <profile>`, `check` | run a profile |
| `dump <file> <size> <expr>` | memory to file |
| `set max N`, `set parallel on\|off` | scan settings |

`help <command>` has examples.

</details>

Tab completion, history in `~/.local/state/patty/history`, Ctrl-C cancels a
scan, Ctrl-D twice quits. You can pipe a file of commands into `patty repl`.

## CLI

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

`-o json` for scripts. Exit code 0 = found, 2 = nothing found (or `check` not
clean), 1 = error.

Files get mapped the way the loader would map them, so addresses match IDA and
RVAs match the running process.

## Profiles

Your sigs for one game in a JSON file:

```json
{
  "name": "toygame",
  "module": "toygame",
  "patterns": [
    { "name": "LocalPlayer", "aob": "48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0",
      "result_offset": 3, "resolve": ["rip"] },
    { "name": "HealthRead", "aob": "48 85 C0 74 04 F3 0F 10 00" }
  ]
}
```

After a game update:

```text
$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 1.3 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x00005557D57A7028  rva 0x00004028
  ok          Tick         0x00005557D57A41F8  rva 0x000011F8
  missing     HealthRead
  ambiguous   Prologue     21 matches
```

`ok` comes with the new RVA. `unresolved` means it matched but the pointer
behind it was null. Exit code is 2 unless everything is `ok`.

Pattern keys: `aob` (or `ida`), `string`, `sso_string` (MSVC `std::string`
object). Optional `result_offset` and `resolve`: `"rip"`, `"deref"`,
`{"type": "add", "extra": 8}`.

## Library

```cmake
find_package(patty CONFIG REQUIRED)   # -DCMAKE_PREFIX_PATH=~/.local
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

Opening a target and parsing patterns/profiles throw `patty::Error`. Reads
don't throw, they return `bool` / `std::optional`. `Scanner` only borrows the
target. Want to scan something else (dumps, remote memory, DMA)? Subclass
`patty::Target` and implement `read`, `regions`, `describe`.

<details>
<summary>API overview</summary>

| | |
|---|---|
| `Process` | `open(pid)`, `open("Game.exe")`, `current()`, `find(name)` |
| `Image` | `open(path)`, `open_raw(path, base)`, `from_bytes(bytes, base)` |
| `Target` | `read<T>`, `read_pointer`, `read_string`, `read_bytes`, `view`, `regions`, `modules`, `module(name)`, `region_at` |
| `Pattern` | `aob`, `text`, `raw`, `integer`, `value`, `msvc_string`; `.rip(n)` `.deref()` `.add(n)` `.named(s)` |
| `Scanner` | `find`, `find_pointer(s)`, `probe`, `check` |
| `ScanOptions` | `module`, `code_only`, `data_only`, `max`, `parallel`, `threads`, `filter`, `cancel` |
| `Profile` | `load`, `parse` |
| | `pointer_chain`, `rip_relative`, `resolve` |

</details>

## Performance

i5-12400F, AVX2, release, best of 5:

| | 1 thread | all threads (default) |
|---|---|---|
| 1 sig, 154 MiB binary | 11-12 ms | 4.4-5 ms |
| 20 sigs, same binary | 98 ms | 16 ms |
| 1 sig, 1 GiB live process | 163 ms | 41 ms |
| opening the 154 MiB binary | 2 ms | |

It searches for the two rarest bytes of each sig (frequency table from a bunch
of real game binaries and libs) and checks 64 positions per step with AVX2, so
a sig starting with `48` isn't any slower. Roughly 20 GB/s per core. Files are
mmapped and scanned in place. Live memory is read in 256 KiB chunks on all
cores; most of that time is the kernel copying.

## Limitations

- Read-only. No writing, freezing, breakpoints or disassembly.
- 32-bit games under Wine's new WoW64 mode show up as 64-bit.
- Windows build compiles (MinGW) but hasn't been run on real Windows yet.
- No macOS.
- API can still change before 1.0.

## Building manually

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
cmake --install build --prefix ~/.local
```

`-DBUILD_SHARED_LIBS=ON`, `-DPATTY_BUILD_CLI=OFF`, `-DPATTY_BUILD_TESTS=OFF`.

## License

Non-commercial, see [LICENSE](LICENSE).
