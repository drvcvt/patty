# patty

patty finds byte signatures in running processes and in binaries on disk,
follows them to the data you actually care about, and after every game update
tells you which of your signatures survived and where things moved.

It's a command line tool, a small interactive shell that borrows a lot from
gdb, and the C++20 library both of them are built on. It only ever reads.

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

Works on Linux and Windows. On Linux patty reads memory through
`process_vm_readv` and that's it: no ptrace attach, no stopped threads, no
`/proc/<pid>/mem`.

**New here?** [TUTORIAL.md](TUTORIAL.md) walks you through a full round on a
tiny toy game in about ten minutes: find a value, trace it back to a global,
turn that into a signature, then survive an update.

## Getting it running

```bash
git clone https://github.com/drvcvt/patty.git
cd patty
scripts/setup.sh
```

The script asks for your sudo password right at the start and never again.
Then it builds, runs the tests, installs to `~/.local` and gives the binary
permission to read other processes. Want it somewhere else? `--prefix DIR`.
No sudo at all? `--no-setcap`. patty can then still read files, and processes
that explicitly allow it, like the toy game from the tutorial.

You need CMake 3.20+, Ninja and a C++20 compiler. The libraries (nlohmann/json,
CLI11, GoogleTest, isocline) get fetched if your system doesn't have them.

### About that sudo

Most distros set `kernel.yama.ptrace_scope` to 1, which means a process may
only read memory of its own children. patty never calls ptrace, but the kernel
checks the same permission for `process_vm_readv`. So `setup.sh` runs
`sudo setcap cap_sys_ptrace=ep` on the patty binary, which lifts that limit for
patty alone instead of for your whole system.

That also means patty can read anyone's processes, root's included, so the
script makes the binary `chmod 700`: only you can run it. And since a rebuild
replaces the file, the capability goes away with it. Run the script again after
rebuilding.

Without the capability you don't get mysteriously empty results, you get this:

```text
patty: not allowed to read pid 979010 (kernel.yama.ptrace_scope=1). patty only uses
process_vm_readv, but the kernel gates it like ptrace. Run scripts/setup.sh once, or:
sudo setcap cap_sys_ptrace=ep $(command -v patty)
```

Windows doesn't have any of this; patty just opens the process for reading.

## The shell

`patty` on its own starts it. `patty repl --name Game.exe` (or `--pid`,
`--file`) opens a target right away.

The idea is the same as in gdb: everything you find gets a number (`$1`, `$2`,
...), `$` is the last one, and you can do math on them and follow pointers with
brackets. `[[$6]+8]` reads the pointer at `$6`, adds 8 and reads again. Module
names work as addresses too (`Game.exe+0x2A4F10`; quote names with a dash in
them, like `'ld-linux-x86-64.so.2'`). Numbers are decimal unless they start with
`0x`, also like gdb.

<details>
<summary>All the commands</summary>

| Command | What it does |
|---|---|
| `proc <pid\|name>` | open a running process |
| `file [-raw] <path>` | open a PE, ELF or raw dump |
| `info`, `maps [text]`, `modules [text]` | what's loaded where |
| `find [flags] <aob \| "text">` | search for a signature or a string |
| `findval <value> [type]` | search for a number: `i8`..`u64`, `float`, `double` |
| `refs <expr>` | find pointers to an address |
| `x[/NFU] <expr>` | look at memory, gdb style (formats `x d u f a s c`, sizes `b h w g`) |
| `p <expr>` | evaluate an address and say where it points |
| `probe [-s size] <expr>` | guess what each field of an object is |
| `load <profile>`, `check` | run a signature profile against the target |
| `dump <file> <size> <expr>` | save memory to a file |
| `set max N`, `set parallel on` | scan defaults |

`find` takes `-c` (code only), `-d` (data only), `-m <module>`, `-n <max>`,
`-o <offset>` and `-r rip,deref,add:8` to follow what it found. `help <command>`
in the shell has examples for each.

</details>

Tab completes commands, module names and file paths, history survives restarts
(`~/.local/state/patty/history`). Ctrl-C stops a scan that takes too long,
Ctrl-D twice gets you out. You can also pipe a file of commands into
`patty repl` and it runs them like a script.

## One-shot commands

For scripts, or when you only need one answer:

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

Add `-o json` to any of them if a program reads the output. The exit code is
`0` when something was found, `2` when nothing was (or a `check` wasn't all
clean) and `1` on errors.

Files are laid out the way the Windows or Linux loader would map them, so an
address from `--file Game.exe` is the one IDA shows you, and RVAs from the file
match the ones from the running game.

## Profiles

A profile is a JSON file with the signatures you care about for one game, and
it's what makes updates bearable:

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

After a patch you run `check` and it tells you, for every signature, whether
it's still `ok` (and its new RVA), `ambiguous` (matches in several places),
`missing`, or `unresolved` (matched, but the pointer it leads to is null right
now). This is from the tutorial, right after the update:

```text
$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 1.3 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x00005557D57A7028  rva 0x00004028
  ok          Tick         0x00005557D57A41F8  rva 0x000011F8
  missing     HealthRead
  ambiguous   Prologue     21 matches
```

Patterns can be `aob` (`ida` works too), `string` or `sso_string` (an MSVC
`std::string` object). `result_offset` and `resolve` (`"rip"`, `"deref"`,
`{"type": "add", "extra": 8}`) say how to get from the match to the address you
want. `check` exits with `2` unless everything is `ok`, so it slots right into
a script that runs after every update.

## Using it as a library

`setup.sh` installs a CMake package, so in your own project:

```cmake
find_package(patty CONFIG REQUIRED)   # configure with -DCMAKE_PREFIX_PATH=~/.local
target_link_libraries(my_tool PRIVATE patty::patty)
```

The tutorial's steps in C++, against the same toy game:

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

A few things that hold everywhere. Opening a target, parsing a pattern or
profile and scanning a module that isn't loaded throw `patty::Error`, with a
message that tells you what went wrong. Reads never throw; they hand back a
`bool`, an `std::optional` or an empty vector. A `Scanner` borrows its target,
so keep the target alive while you scan. And if you want to scan something
patty doesn't know (a dump format, a remote machine, a DMA card), derive from
`patty::Target`, implement `read`, `regions` and `describe`, and every scanner
feature works on it.

<details>
<summary>What's in the box</summary>

| | |
|---|---|
| `Process` | `open(pid)`, `open("Game.exe")`, `current()`, `find(name)` |
| `Image` | `open(path)` maps PE/ELF like a loader, `open_raw(path, base)`, `from_bytes(bytes, base)` |
| `Target` | shared by both: `read<T>`, `read_pointer`, `read_string`, `read_bytes`, `view` (zero-copy), `regions`, `modules`, `module(name)`, `region_at` |
| `Pattern` | `aob`, `text`, `raw(bytes, mask)`, `integer(v, size)`, `value(x)`, `msvc_string`, chained with `.rip(n)`, `.deref()`, `.add(n)`, `.named(s)` |
| `Scanner` | `find(pattern)`, `find(patterns)` in one pass, `find_pointer(s)`, `probe`, `check(profile)` |
| `ScanOptions` | `module`, `code_only`, `data_only`, `max`, `parallel`, `threads`, `filter`, `cancel` |
| `Profile` | `load(path)`, `parse(json)` |
| free functions | `pointer_chain`, `rip_relative`, `resolve` |

</details>

## How fast

Measured on an i5-12400F (6 cores, AVX2), release build, best of five:

| | one core | all cores (default) |
|---|---|---|
| one signature over a 154 MiB binary | 11 to 12 ms | 4.4 to 5 ms |
| 20 signatures over the same binary | 98 ms | 16 ms |
| one signature over 1 GiB of a running process | 163 ms | 41 ms |
| opening that 154 MiB binary | 2 ms | |

The search looks for the two bytes of a signature that are rarest in real
x86-64 code (the table comes from a byte count over a handful of games and
libraries) and checks 64 positions at a time with AVX2. So it doesn't matter
whether your signature starts with something boring like `48`: one core does
about 20 GB/s either way, which is about as fast as it can read memory anyway.
Binaries on disk are memory-mapped and scanned in place. Live memory gets
copied in 256 KiB pieces on every core, and that copy is most of the cost; on
a single core the kernel spends about two thirds of the time just moving
bytes.

## What it won't do

It doesn't write memory, freeze values, set breakpoints or disassemble. 32-bit
Windows games running under the newer WoW64 mode of Wine are reported as
64-bit. Windows support compiles (checked with MinGW) but hasn't run on an
actual Windows machine yet, and there's no macOS. The API may still change
before 1.0.

## Optional: MCP server

`mcp/` has a small server that lets Claude Code and other MCP clients drive
patty. Nothing depends on it; `scripts/setup.sh --mcp` sets it up and
[mcp/README.md](mcp/README.md) has the details.

## Building by hand

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
cmake --install build --prefix ~/.local
```

`-DBUILD_SHARED_LIBS=ON` builds a shared library, `-DPATTY_BUILD_CLI=OFF` and
`-DPATTY_BUILD_TESTS=OFF` leave out the tool and the tests.

```text
include/patty/   public headers: memory/ (targets), scan/ (patterns, scanner), profile/
src/             the library
cli/             the command line tool, cli/repl/ is the shell
examples/        toygame.c and its profile, used by the tutorial
scripts/         setup.sh
mcp/             the optional MCP server
```

## License

Non-commercial, see [LICENSE](LICENSE).
