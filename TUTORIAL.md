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
toygame 1.0, pid 2281406
```

toygame allows other processes to read it, so no sudo/setcap needed here. For
a real game you need `setup.sh` first.

## 1. Find the value

Player has 87.5 health. `patty <name>` opens the process and drops you into
the shell:

```text
$ patty toygame
opened pid 2281406 (toygame)
patty toygame:2281406> findval 87.5
Scanned 2.4 MB in 0.6 ms

[87.5 float] 3 matches
  $1    0x00005631B5AA2263  toygame+0x1263 r-x
  $2    0x00005631D081E030  rw- [heap]
  $3    0x00007FFCA3AE706C  rw- [stack]
```

Has a decimal point, so it's searched as float. Hit 1 is the constant in the
binary's code, 3 is on the stack, 2 on the heap is the actual player.

## 2. Look at the object

```text
patty toygame:2281406> probe -s 0x18 $2
Probed 24 B at 0x00005631D081E030

  +0     0x0000000C42AF0000  float       87.500000
  +8     0x00005631B5AA300A  string_ptr  PlayerOne
  +10    0x00005631D081E010  pointer     -> 0x5631D081E010
```

Health at `+0` (the upper half of that qword is the level, 12), name pointer
at `+8`, some other pointer at `+10`.

## 3. Find what points to it

Heap addresses change every run, so look for a pointer to `$2`:

```text
patty toygame:2281406> refs $2
Scanned 2.4 MB in 0.2 ms

[pointer_0x5631D081E030] 1 match
  $4    0x00005631B5AA5020  toygame+0x4020 rw-
```

It's in the binary's writable data at `toygame+0x4020`, so it's a global. That
offset is stable until the next update.

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

Test it. `-c` = code only, `-m toygame` = only this module, `-r 3` = the
rip-relative operand starts at byte 3, follow it:

```text
patty toygame:2281406> find -c -m toygame -r 3 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.1 ms

1 match
  $5    0x00005631B5AA21ED -> 0x00005631B5AA5020  toygame+0x11ED r-x
```

Unique, and it resolves to `$4` from step 3.

## 5. Follow pointers

`[...]` reads a pointer:

```text
patty toygame:2281406> x/s [[$5]+8]
0x00005631B5AA300A  "PlayerOne"
patty toygame:2281406> p [[$5]+0x10]
$6 = 0x00005631D081E010  rw- [heap]
patty toygame:2281406> x/fw $
0x00005631D081E010  40
```

`[$5]` is the player, `+8` the name, `+0x10` points to another player with 40
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

  ok          LocalPlayer  0x00005631B5AA5020  rva 0x00004020
  ok          Tick         0x00005631B5AA21E9  rva 0x000011E9
  ok          HealthRead   0x00005631B5AA21F8  rva 0x000011F8
  ambiguous   Prologue     20 matches
```

## 7. Update

1.1 adds a `team` field at the start of the struct and a new global:

```console
$ kill %1
$ gcc -O1 -DPATCH -o toygame examples/toygame.c
$ ./toygame &
toygame 1.1, pid 2281470
$ patty check --name toygame --profile examples/toygame.json
Checked 4 pattern(s) over 20 KB in 0.3 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x000055F958021028  rva 0x00004028
  ok          Tick         0x000055F95801E1F8  rva 0x000011F8
  missing     HealthRead
  ambiguous   Prologue     21 matches
```

`LocalPlayer` still works and gives you the new offset, `0x4028`. `Tick`
moved but still matches. `HealthRead` broke, which tells you the struct
changed. Check it:

```text
$ patty toygame
opened pid 2281470 (toygame)
patty toygame:2281470> find -c -m toygame -r 3 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
Scanned 4 KB in 0.1 ms

1 match
  $1    0x000055F95801E1FC -> 0x000055F958021028  toygame+0x11FC r-x
patty toygame:2281470> x/4dw [$1]
0x000055F98FDD9040  1 1118765056 12 0
patty toygame:2281470> x/fw [$1]+4
0x000055F98FDD9044  87.5
```

`1` is the new team field, `1118765056` is 87.5 as an int. Health is at `+4`
now. New `HealthRead`: `48 85 C0 74 05 F3 0F 10 40 04`. Drop `Prologue`.

## Next

- Real game: `scripts/setup.sh`, then `patty Game.exe`. `ps` (in the shell or
  as `patty ps`) lists processes; Proton/Wine games show up with their exe name.
- `patty check` exits with 2 if anything isn't `ok`, so you can run it from a
  script after every patch.
- C++ version of the same steps: README, "Library".
- `help` / `help <command>` in the shell.
