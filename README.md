# patty

Sig scanner for live processes and PE/ELF files, Linux and Windows. CLI, a
gdb-ish shell and a C++20 library.

Read-only. On Linux it only uses `process_vm_readv`: no ptrace attach, nothing
gets stopped, no `/proc/<pid>/mem`.

```text
$ patty toygame
opened pid 2281406 (toygame)
patty toygame:2281406> find -c -m toygame -r 3 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.1 ms

1 match
  $5    0x00005631B5AA21ED -> 0x00005631B5AA5020  toygame+0x11ED r-x
patty toygame:2281406> x/s [[$5]+8]
0x00005631B5AA300A  "PlayerOne"
patty toygame:2281406> p [[$5]+0x10]
$6 = 0x00005631D081E010  rw- [heap]
patty toygame:2281406> x/fw $
0x00005631D081E010  40
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
patty Game.exe      # process name, pid or a file, whatever you give it
patty               # empty shell; then `ps` and `open <pid|name|file>`
```

Results get numbered like in gdb: `$1`, `$2`, `$` is the last one, and every
hit shows where it is (`Game.exe+0x11ED r-x`, `rw- [heap]`).
Expressions work anywhere an address goes: `Game.exe+0x2A4F10`, `[$1]+0x18`
(brackets read a pointer), `0x` for hex, quotes around module names with a
dash (`'ld-linux-x86-64.so.2'`).

<details>
<summary>commands</summary>

| | |
|---|---|
| `open [-raw] <pid\|name\|file>` | open a process or a binary/dump |
| `ps [text]` | list processes |
| `info`, `maps [text]`, `modules [text]` | what's loaded where |
| `find [-c] [-d] [-m mod] [-n max] [-r 3] <aob \| "text">` | sig or string search, `-r 3` follows a rip operand at byte 3 |
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
scan, Ctrl-D twice quits. Piping works too: `patty Game.exe < steps.txt` runs the commands in the file.

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
patty ps steam
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
#include <format>

using namespace patty::literals;

// How toygame lays out a player. Remote<T> is a pointer that lives in the game.
struct Player {
    float health;
    int level;
    patty::Remote<char> name;
    patty::Remote<Player> target;
};

int main() try {
    auto game = patty::Process::open("toygame");
    patty::Scanner scan{game};

    // mov rax, [rip+g_local] ; pxor xmm0, xmm0 ; test rax, rax
    auto hits = scan.find("48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0"_sig.rip(3), {.module = "toygame"});
    if (hits.size() != 1) {
        std::puts("signature broke, time to update it");
        return 1;
    }

    auto local = game.read(hits[0].as<patty::Remote<Player>>()).value();
    auto player = game.read(local).value();
    std::puts(std::format("{} at {:#x}: {} hp, level {}", game.read_string(player.name).value_or("?"),
                          local, player.health, player.level).c_str());

    if (auto hp = game.read(local, &Player::target, &Player::health))
        std::puts(std::format("its target has {} hp", *hp).c_str());
} catch (const std::exception& e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
}
```

```text
PlayerOne at 0x555df1f9c030: 87.5 hp, level 12
its target has 40 hp
```

What's going on there:

- `Remote<T>` is a pointer that lives in the target. It has the target's
  pointer size, so you can put it straight into the structs you read, and
  `game.read(remote)` gives you an `optional<T>`.
- `game.read(local, &Player::target, &Player::health)` walks the members:
  read `local`, follow `target`, read `health`. Null on the way means empty
  optional, not a crash.
- `"..."_sig` is checked while compiling. `"48 8G"_sig` doesn't build.
- `find_value(87.5f)` searches for any trivially copyable value,
  `read_array<T>(addr, n)` reads n of them, `std::format("{:#x}", remote)` works.

Opening a target and parsing patterns/profiles throw `patty::Error`. Reads
don't throw, they return `bool` / `std::optional`. `Scanner` only borrows the
target. Want to scan something else (dumps, remote memory, DMA)? Subclass
`patty::Target` and implement `read`, `regions`, `describe`.

<details>
<summary>API overview</summary>

| | |
|---|---|
| types | `Address`, `Remote<T>` / `Remote32<T>`, concept `Readable`, `offset_of(&T::m)` |
| `Process` | `open(pid)`, `open("Game.exe")`, `current()`, `find(name)`, `list()` |
| `Image` | `open(path)`, `open_raw(path, base)`, `from_bytes(bytes, base)` |
| `Target` | `read<T>(addr)`, `read(remote)`, `read(remote, &T::a, &U::b...)`, `read_array<T>`, `read_string`, `read_pointer`, `view`, `regions`, `modules`, `module(name)` |
| `Pattern` | `"..."_sig`, `aob`, `text`, `raw`, `integer`, `value`, `msvc_string`; `.rip(n)` `.deref()` `.add(n)` `.named(s)` |
| `Scanner` | `find(sig)`, `find({a, b})`, `find_value(v)`, `find_pointer(s)`, `probe`, `check` |
| `Match` | `address`, `resolved`, `value()`, `as<T>()` |
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
