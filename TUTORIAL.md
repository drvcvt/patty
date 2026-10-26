# Your first ten minutes with patty

No game needed. `examples/toygame.c` is a forty line program with a player
struct behind a global pointer, which is exactly the situation you're in with
most real games, just without the anti-cheat and the 40 GB download.

We'll find the player's health, figure out which global points to it, turn the
code that reads that global into a signature, and then ship a "game update"
that breaks half of our work, so you can see how patty tells you what to fix.

Everything below is real output. Your addresses will differ, the offsets won't.

## 0. Build the toy

You need patty built (`scripts/setup.sh`, or the steps in the README) and gcc.

```console
$ gcc -O1 -o toygame examples/toygame.c
$ ./toygame &
toygame 1.0, pid 2029764
```

toygame lets any of your processes read it, so this works without the sudo
step. A real game needs `setup.sh` to have done its thing.

## 1. Find the value you can see

The player has 87.5 health. In a real game you'd read that off the HUD. Start
the shell, open the process and look for the number:

```text
patty> proc toygame
opened pid 2029764 (toygame)
patty toygame:2029764> findval 87.5
Scanned 2.4 MB in 0.5 ms

[87.5 float] 3 matches
  $1    0x000055BAD5B45263  toygame
  $2    0x000055BB1243E030  [heap]
  $3    0x00007FFE8E241C3C  [stack]
```

`87.5` has a decimal point, so patty searched for a float. Three hits: one is
the constant inside the binary, one sits on the stack, and the one on the heap
is the live player. Every match got a number, `$2` is the one we want.

## 2. Look around it

```text
patty toygame:2029764> probe -s 0x18 $2
Probed 24 B at 0x000055BB1243E030

  +0     0x0000000C42AF0000  float       87.500000
  +8     0x000055BAD5B4600A  string_ptr  PlayerOne
  +10    0x000055BB1243E010  pointer     -> 0x55BB1243E010
```

`probe` guesses what each 8-byte field is. Health at `+0` (with the level, 12,
in the upper half of the same 8 bytes), a pointer to the name at `+8`, and a
pointer to something else at `+10`. Hold that thought.

## 3. Who points at the player?

Heap addresses change on every start, so we need something stable that leads
there. Ask which memory holds a pointer to `$2`:

```text
patty toygame:2029764> refs $2
Scanned 2.4 MB in 0.5 ms

[pointer_0x55BB1243E030] 1 match
  $4    0x000055BAD5B48020  toygame
patty toygame:2029764> p $4
$5 = 0x000055BAD5B48020  toygame+0x4020 rw-
```

A pointer inside the binary's own writable data, at `toygame+0x4020`. That's a
global, and globals stay where they are relative to the module. In a real game
this is the moment you write `0x4020` down.

## 4. Turn it into a signature

`0x4020` is good until the next update moves it. What survives updates much
better is the *code* that reads the global. You'd normally go to IDA for this;
objdump does the job for toygame:

```console
$ objdump -d --disassemble=tick toygame
00000000000011e9 <tick>:
    11e9:	f3 0f 1e fa          	endbr64
    11ed:	48 8b 05 2c 2e 00 00 	mov    0x2e2c(%rip),%rax        # 4020 <g_local>
    11f4:	66 0f ef c0          	pxor   %xmm0,%xmm0
    11f8:	48 85 c0             	test   %rax,%rax
    11fb:	74 04                	je     1201 <tick+0x18>
    11fd:	f3 0f 10 00          	movss  (%rax),%xmm0
    1201:	c3                   	ret
```

Take the `mov` and the two instructions after it, and replace the four bytes
of the displacement with wildcards, because those are exactly what changes when
the global moves:

```
48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
```

Now check that it finds one place, and that following it lands on the global
from step 3. `-c` searches code only, `-m toygame` stays inside the binary,
`-o 3 -r rip` skips the three opcode bytes and resolves the rip-relative operand:

```text
patty toygame:2029764> find -c -m toygame -o 3 -r rip 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.2 ms

1 match
  $6    0x000055BAD5B451ED -> 0x000055BAD5B48020  toygame
```

One match, and `-> ...8020` is `$4`. That signature is the thing to keep.

## 5. Walk the pointers

With `[...]` reading a pointer, you can go from the signature all the way to
the data:

```text
patty toygame:2029764> x/s [[$6]+8]
0x000055BAD5B4600A  "PlayerOne"
patty toygame:2029764> p [[$6]+0x10]
$7 = 0x000055BB1243E010  rw- [heap]
patty toygame:2029764> x/fw $
0x000055BB1243E010  40
```

`[$6]` is the player, `+8` its name. The mystery pointer at `+0x10` leads to
another player with 40 health, the enemy it's targeting.

## 6. Keep it in a profile

Signatures you want to keep go into a profile. `examples/toygame.json` has the
one from step 4 plus three more, to make the next part interesting:

```json
{
  "name": "toygame",
  "version": "1.0",
  "module": "toygame",
  "patterns": [
    { "name": "LocalPlayer", "aob": "48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0",
      "result_offset": 3, "resolve": ["rip"] },
    { "name": "Tick", "aob": "F3 0F 1E FA 48 8B 05 ?? ?? ?? ?? 66 0F EF C0" },
    { "name": "HealthRead", "aob": "48 85 C0 74 04 F3 0F 10 00" },
    { "name": "Prologue", "aob": "F3 0F 1E FA" }
  ]
}
```

`HealthRead` covers the `movss (%rax)` that reads health, so it bakes in the
assumption that health sits at `+0`. `Prologue` is a bad signature on purpose:
every function starts with those four bytes.

```console
$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 0.3 ms: 3 ok, 1 ambiguous, 0 missing

  ok          LocalPlayer  0x000055BAD5B48020  rva 0x00004020
  ok          Tick         0x000055BAD5B451E9  rva 0x000011E9
  ok          HealthRead   0x000055BAD5B451F8  rva 0x000011F8
  ambiguous   Prologue     20 matches
```

## 7. The update

Version 1.1 adds a `team` field at the front of the player and a new global.
That's a perfectly normal patch, and it moves things around:

```console
$ kill %1
$ gcc -O1 -DPATCH -o toygame examples/toygame.c
$ ./toygame &
toygame 1.1, pid 2030539
$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 1.3 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x00005557D57A7028  rva 0x00004028
  ok          Tick         0x00005557D57A41F8  rva 0x000011F8
  missing     HealthRead
  ambiguous   Prologue     21 matches
```

Read it top to bottom:

`LocalPlayer` still matches, and the global moved from `0x4020` to `0x4028`.
That's your new offset, no reversing needed. `Tick` moved too and is still
fine. `HealthRead` is gone, and that's the useful part: the code that reads
health changed, which means the struct changed. Time to look:

```text
patty toygame:2030539> find -c -m toygame -o 3 -r rip 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.1 ms

1 match
  $1    0x00005557D57A41FC -> 0x00005557D57A7028  toygame
patty toygame:2030539> x/4dw [$1]
0x00005557DB2B3040  1 1118765056 12 0
patty toygame:2030539> x/fw [$1]+4
0x00005557DB2B3044  87.5
```

A new `1` in front (the team), then 1118765056, which is 87.5 read as an
integer: health is at `+4` now. Fix `HealthRead` to
`48 85 C0 74 05 F3 0F 10 40 04`, maybe throw `Prologue` away, and the profile
is ready for 1.1.

That loop is most of what patty is for: find it once, write it down as a
signature, and after every update let `check` tell you what moved and what
broke.

## Where to go from here

- A real game: run `scripts/setup.sh` once, then `patty repl --name Game.exe`.
  Proton and Wine games are found by their Windows exe name, and their modules
  usually show up under their file names (`Game.exe`, `UnityPlayer.dll`), so
  `-m Game.exe` works. `modules` in the shell shows what's there.
- Put `patty check` in a script that runs after every patch. It exits with `2`
  as soon as anything isn't `ok`.
- The same steps from C++ are in the README under "Using patty as a library".
- `help` in the shell, and `help <command>` for the details of each one.
