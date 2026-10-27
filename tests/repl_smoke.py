"""Pipes a session into `patty repl` and checks the transcript."""
import re
import subprocess
import sys
from pathlib import Path

fixture = Path(sys.argv[1])
exe = Path(sys.argv[2])
profile = fixture.with_name('patty-smoke.profile.json')

commands = f'''
find "Hello"
p $1+2
x/s $1
x/2xg 0x20
p [0x20]+0x10
findval 0x40 u64
refs 0x40
load {profile}
check
p nonsense
p $99
x/q 0
bogus
fnid 00
open {fixture}
find -r 0 40 00 00 00
ps patty
quit
info
'''

out = subprocess.run([str(exe), 'repl', '--file', str(fixture)], input=commands,
                     capture_output=True, text=True, timeout=30, check=True).stdout

expected = [
    'opened patty-smoke.bin (raw)',
    '$1    0x0000000000000050',
    '$2 = 0x0000000000000052  patty-smoke.bin+0x52',
    '0x0000000000000050  "Hello World"',
    '0x0000000000000020  0x0000000000000040 0x0000000000000040',
    '$3 = 0x0000000000000050',                  # [0x20] reads 0x40, +0x10
    '[0x40 u64] 2 matches',
    '[pointer_0x40] 2 matches',
    'loaded 3 patterns from patty smoke',
    '1 ok, 1 ambiguous, 1 missing',
    'ok          Hello        0x0000000000000050  rva 0x00000050',
    'error: no module named "nonsense" at column 1',
    'error: $99 does not exist',
    "error: unknown x format letter 'q'",
    'unknown command "bogus"',
    'unknown command "fnid", did you mean find?',
    '$1    0x0000000000000050  patty-smoke.bin+0x50 r-x',
    '0x0000000000000020 -> 0x0000000000000064',  # -r 0: rel32 at the match itself
]
for line in expected:
    assert line in out, f'missing {line!r} in:\n{out}'
assert out.count('opened patty-smoke.bin (raw)') == 2, out  # start + open
assert re.search(r'^\s*\d+  patty$', out, re.M), 'ps did not list patty itself:\n' + out
assert 'readable' not in out, 'commands after quit ran:\n' + out
print('repl-smoke-ok')
