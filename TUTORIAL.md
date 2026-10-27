# Tutorial

Uses `examples/toygame.c`, a small program with a player struct behind a
global pointer. Steps: find the health value, find the global that points to
it, make a sig for the code that reads the global, then rebuild the toy as
"version 1.1" and see what `check` says.

All output below is from real runs. Addresses will be different for you,
offsets won't.

## 0. Build the toy

Needs patty (see README) and gcc.

```console
$ gcc -O1 -o toygame examples/toygame.c
$ ./toygame &
toygame 1.0, pid 2029764
```

toygame allows other processes to read it, so no sudo/setcap needed here. For
a real game you need `setup.sh` first.

## 1. Find the value

Player has 87.5 health:

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

Has a decimal point, so it's searched as float. Hit 1 is the constant in the
binary, 3 is on the stack, 2 on the heap is the actual player.

## 2. Look at the object

```text
patty toygame:2029764> probe -s 0x18 $2
Probed 24 B at 0x000055BB1243E030

  +0     0x0000000C42AF0000  float       87.500000
  +8     0x000055BAD5B4600A  string_ptr  PlayerOne
  +10    0x000055BB1243E010  pointer     -> 0x55BB1243E010
```

Health at `+0` (the upper half of that qword is the level, 12), name pointer
at `+8`, some other pointer at `+10`.

## 3. Find what points to it

Heap addresses change every run, so look for a pointer to `$2`:

```text
patty toygame:2029764> refs $2
Scanned 2.4 MB in 0.5 ms

[pointer_0x55BB1243E030] 1 match
  $4    0x000055BAD5B48020  toygame
patty toygame:2029764> p $4
$5 = 0x000055BAD5B48020  toygame+0x4020 rw-
```

It's in the binary's data at `toygame+0x4020`, so it's a global. That offset is
stable until the next update.

## 4. Make a sig

To survive updates, sig the code that reads the global instead of hardcoding
`0x4020`. Normally you'd do this in IDA, objdump is enough here:

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

Take the `mov` plus the next two instructions and wildcard the 4 displacement
bytes, since those change when the global moves:

```
48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
```

Test it. `-c` = code only, `-m toygame` = only this module, `-o 3 -r rip` =
skip the 3 opcode bytes and resolve the rip-relative operand:

```text
patty toygame:2029764> find -c -m toygame -o 3 -r rip 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.2 ms

1 match
  $6    0x000055BAD5B451ED -> 0x000055BAD5B48020  toygame
```

Unique, and it resolves to `$4` from step 3.

## 5. Follow pointers

`[...]` reads a pointer:

```text
patty toygame:2029764> x/s [[$6]+8]
0x000055BAD5B4600A  "PlayerOne"
patty toygame:2029764> p [[$6]+0x10]
$7 = 0x000055BB1243E010  rw- [heap]
patty toygame:2029764> x/fw $
0x000055BB1243E010  40
```

`[$6]` is the player, `+8` the name, `+0x10` points to another player with 40
health (the target).

## 6. Profile

`examples/toygame.json` has the sig from step 4 plus three others:

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

`HealthRead` includes the `movss (%rax)`, so it depends on health being at
`+0`. `Prologue` is a bad sig on purpose, every function starts with it.

```console
$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 0.3 ms: 3 ok, 1 ambiguous, 0 missing

  ok          LocalPlayer  0x000055BAD5B48020  rva 0x00004020
  ok          Tick         0x000055BAD5B451E9  rva 0x000011E9
  ok          HealthRead   0x000055BAD5B451F8  rva 0x000011F8
  ambiguous   Prologue     20 matches
```

## 7. Update

1.1 adds a `team` field at the start of the struct and a new global:

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

`LocalPlayer` still works and gives you the new offset, `0x4028`. `Tick`
moved but still matches. `HealthRead` broke, which tells you the struct
changed. Check it:

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

`1` is the new team field, `1118765056` is 87.5 as an int. Health is at `+4`
now. New `HealthRead`: `48 85 C0 74 05 F3 0F 10 40 04`. Drop `Prologue`.

## Next

- Real game: `scripts/setup.sh`, then `patty repl --name Game.exe`. Proton/Wine
  games are found by their exe name, `modules` lists what's loaded.
- `patty check` exits with 2 if anything isn't `ok`, so you can run it from a
  script after every patch.
- C++ version of the same steps: README, "Library".
- `help` / `help <command>` in the shell.
