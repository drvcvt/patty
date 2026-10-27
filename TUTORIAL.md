# Tutorial

Uses `examples/toygame.c`, a small program with a player struct behind a
global pointer. Steps: find the health value, narrow it down after taking
damage, find the global that points to the player, make a sig for the code
that reads the global, then rebuild the toy as "version 1.1" and see what
`check` says.

All output below is from real runs. Addresses will be different for you,
offsets won't.

## 0. Build the toy

Needs patty (see README) and gcc.

```console
$ gcc -O1 -o toygame examples/toygame.c
$ ./toygame &
toygame 1.0, pid 2407831
```

toygame allows other processes to read it, so no sudo/setcap needed here. For
a real game you need `setup.sh` first. `kill -USR1 <pid>` makes the player
take 10 damage.

## 1. Find the value

Player has 87.5 health. `patty <name>` opens the process and drops you into
the shell:

```text
$ patty toygame
opened pid 2407831 (toygame)
patty toygame:2407831> findval 87.5
2 matches  (2.4 MB, 0.4 ms)
  $1    0x000055E0D63782BB  toygame+0x12BB r-x
  $2    0x000055E0EE929030  rw- [heap]
```

Has a decimal point, so it's searched as float. `$1` is a constant in the
code, `$2` on the heap is probably the player. In a real game you'd get
hundreds of hits here, so narrow it down: take damage (`kill -USR1 2407831`
in another terminal) and keep only what went down:

```text
patty toygame:2407831> filter float decreased
  $3    0x000055E0EE929030  77.5  rw- [heap]
1 of 2 left
patty toygame:2407831> $player = $3
$player = 0x000055E0EE929030  rw- [heap]
```

`filter` works on the last hits; you can repeat it as often as you need.
`$player = ...` gives the address a name.

## 2. Look at the object

```text
patty toygame:2407831> probe -s 0x18 $player
Probed 24 B at 0x000055E0EE929030

  +0     0x0000000C429B0000  float       77.500000
  +8     0x000055E0D637900E  string_ptr  PlayerOne
  +10    0x000055E0EE929010  pointer     -> 0x55E0EE929010
```

Health at `+0` (the upper half of that qword is the level, 12), name pointer
at `+8`, some other pointer at `+10`.

## 3. Find what points to it

Heap addresses change every run, so look for a pointer to the player:

```text
patty toygame:2407831> refs $player
1 match  (2.4 MB, 1.6 ms)
  $4    0x000055E0D637B020  toygame+0x4020 rw-
```

It's in the binary's writable data at `toygame+0x4020`, so it's a global. That
offset is stable until the next update.

## 4. Make a sig

To survive updates, sig the code that reads the global instead of hardcoding
`0x4020`. Normally you'd do this in IDA, objdump is enough here:

```console
$ objdump -d --disassemble=tick toygame
0000000000001245 <tick>:
    1245:	f3 0f 1e fa          	endbr64
    1249:	48 8b 05 d0 2d 00 00 	mov    0x2dd0(%rip),%rax        # 4020 <g_local>
    1250:	66 0f ef c0          	pxor   %xmm0,%xmm0
    1254:	48 85 c0             	test   %rax,%rax
    1257:	74 04                	je     125d <tick+0x18>
    1259:	f3 0f 10 00          	movss  (%rax),%xmm0
    125d:	c3                   	ret
```

Take the `mov` plus the next two instructions and wildcard the 4 displacement
bytes, since those change when the global moves:

```
48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
```

Test it. `-c` = code only, `-m toygame` = only this module, `-r 3` = the
rip-relative operand starts at byte 3, follow it:

```text
patty toygame:2407831> find -c -m toygame -r 3 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
1 match  (4 KB, 0.4 ms)
  $5    0x000055E0D6378249 -> 0x000055E0D637B020  toygame+0x1249 r-x
```

Unique, and it resolves to `$4` from step 3.

## 5. Follow pointers

`[...]` reads a pointer:

```text
patty toygame:2407831> read str [[$5]+8]
0x000055E0D637900E  "PlayerOne"
patty toygame:2407831> read float [[$5]+0x10]
0x000055E0EE929010  40
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
$ patty toygame check examples/toygame.json
Checked 4 pattern(s) over 20 KB in 0.3 ms: 3 ok, 1 ambiguous, 0 missing

  ok          LocalPlayer  0x000055E0D637B020  rva 0x00004020
  ok          Tick         0x000055E0D6378245  rva 0x00001245
  ok          HealthRead   0x000055E0D6378254  rva 0x00001254
  ambiguous   Prologue     25 matches
```

## 7. Update

1.1 adds a `team` field at the start of the struct and a new global:

```console
$ kill %1
$ gcc -O1 -DPATCH -o toygame examples/toygame.c
$ ./toygame &
toygame 1.1, pid 2408975
$ patty toygame check examples/toygame.json
Checked 4 pattern(s) over 20 KB in 0.3 ms: 2 ok, 1 ambiguous, 1 missing

  ok          LocalPlayer  0x000055B371D0E028  rva 0x00004028
  ok          Tick         0x000055B371D0B256  rva 0x00001256
  missing     HealthRead
  ambiguous   Prologue     26 matches
```

`LocalPlayer` still works and gives you the new offset, `0x4028`. `Tick`
moved but still matches. `HealthRead` broke, which tells you the struct
changed. Check it:

```text
$ patty toygame
opened pid 2408975 (toygame)
patty toygame:2408975> find -c -m toygame -r 3 48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0
1 match  (4 KB, 0.1 ms)
  $1    0x000055B371D0B25A -> 0x000055B371D0E028  toygame+0x125A r-x
patty toygame:2408975> read -n 4 i32 [$1]
0x000055B37AA4A040  1
0x000055B37AA4A044  1118765056
0x000055B37AA4A048  12
0x000055B37AA4A04C  0
patty toygame:2408975> read float [$1]+4
0x000055B37AA4A044  87.5
```

`1` is the new team field, `1118765056` is 87.5 read as an int. Health is at
`+4` now. New `HealthRead`: `48 85 C0 74 05 F3 0F 10 40 04`. Drop `Prologue`.

## 8. The same from a script

Every shell command also runs as `patty <target> <command>`. In a pipe the
output turns into tab-separated lines with the address first, and `-` reads
addresses from stdin, so steps 1 and 3 work without the shell too. Quote
signatures and `[...]`, otherwise your shell tries to expand them. (This was
a fresh toygame, hence the other pid.)

```console
$ patty toygame findval 87.5 | patty toygame read float - > hp.txt
2 matches  (2.4 MB, 0.7 ms)
$ kill -USR1 2408655
$ patty toygame filter float decreased - < hp.txt
0x000055EBDC5BC030	77.5
1 of 2 left
$ patty toygame find -c -r 3 "48 8B 05 ?? ?? ?? ?? 66 0F EF C0 48 85 C0" | patty toygame read ptr -
1 match  (1.6 MB, 0.3 ms)
0x000055EBDBD85020	0x000055EBDC5BC030
```

The "matches" lines go to stderr, so only results end up in files and pipes.

## Next

- Real game: `scripts/setup.sh`, then `patty Game.exe`. `ps` (in the shell or
  as `patty ps`) lists processes; Proton/Wine games show up with their exe name.
- `patty <target> check <profile>` exits with 2 if anything isn't `ok`, so you
  can run it from a script after every patch.
- C++ version of the same steps: README, "Library".
- `help` / `help <command>` in the shell.
