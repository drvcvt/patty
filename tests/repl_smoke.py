"""A shell script piped into `patty <file>`, checked in table form."""
import subprocess
import sys
from pathlib import Path

fixture = Path(sys.argv[1])
exe = Path(sys.argv[2])
profile = fixture.with_name('patty-smoke.profile.json')

script = f'''
find Hello
p $1+2
x/s $1
read str $1
x/2xg 0x20
p [0x20]+0x10
findval 0x40 u64
filter u64 == 64
filter u64 unchanged
$hello = 0x50
read -n 2 u8 $hello
refs 0x40
check {profile}
p nonsense
p $99
p $nope
x/q 0
fnid 00
open {fixture}
find -r 0 40 00 00 00
quit
info
'''

result = subprocess.run([str(exe), '--table', str(fixture)], input=script,
                        capture_output=True, text=True, timeout=30)
out, err = result.stdout, result.stderr

expected_out = [
    'opened patty-smoke.bin (raw)',
    '1 match  (257 B,',
    '$1    0x0000000000000050  patty-smoke.bin+0x50 r-x',
    '$2 = 0x0000000000000052  patty-smoke.bin+0x52 r-x',
    '0x0000000000000050  "Hello World"',
    '0x0000000000000020  0x0000000000000040 0x0000000000000040',
    '$3 = 0x0000000000000050',                  # [0x20] reads 0x40, +0x10
    '2 matches',
    '0x0000000000000020  64  patty-smoke.bin+0x20 r-x',  # filter keeps both, with values
    '2 of 2 left',
    '$hello = 0x0000000000000050',
    '0x0000000000000051  101',                  # 'e'
    'Checked 3 pattern(s)',
    'ok          Hello        0x0000000000000050  rva 0x00000050',
    '0x0000000000000020 -> 0x0000000000000064',  # -r 0: rel32 at the hit itself
]
for line in expected_out:
    assert line in out, f'missing {line!r} in stdout:\n{out}'

expected_err = [
    'error: no module named "nonsense" at column 1',
    'error: $99 does not exist',
    'error: $nope is not set',
    "error: unknown x format letter 'q'",
    'unknown command "fnid", did you mean find?',
]
for line in expected_err:
    assert line in err, f'missing {line!r} in stderr:\n{err}'

assert out.count('opened patty-smoke.bin (raw)') == 2, out
assert 'readable' not in out, 'commands after quit ran:\n' + out
assert result.returncode == 1, 'a script with failing commands exits 1'
print('repl-smoke-ok')
