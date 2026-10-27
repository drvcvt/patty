"""patty in pipes: clean stdout, stderr for status, '-' input, JSON Lines, exit codes."""
import json
import os
import subprocess
import sys
from pathlib import Path

fixture = Path(sys.argv[1])
exe = Path(sys.argv[2])
profile = fixture.with_name('patty-smoke.profile.json')


def patty(*args, stdin=None, env=None):
    return subprocess.run([str(exe), *args], input=stdin, capture_output=True, text=True, timeout=30,
                          env={**os.environ, **(env or {})})


def lines(result):
    return [line.split('\t') for line in result.stdout.splitlines()]


# Hits: value, address, where. Status goes to stderr, stdout only has results.
hits = patty(str(fixture), 'findval', '0x40', 'u64')
assert hits.returncode == 0, hits
assert lines(hits) == [['0x0000000000000020', '0x0000000000000020', 'patty-smoke.bin+0x20 r-x'],
                       ['0x0000000000000028', '0x0000000000000028', 'patty-smoke.bin+0x28 r-x']], hits.stdout
assert '2 matches' in hits.stderr and '2 matches' not in hits.stdout, hits

# patty into patty: the hits become read's input.
reads = patty(str(fixture), 'read', 'u64', '-', stdin=hits.stdout)
assert lines(reads) == [['0x0000000000000020', '64'], ['0x0000000000000028', '64']], reads

# '-' skips anything that does not start with a number.
messy = 'a header line\n\n  $1 0x20 table junk\n0x50\tfrom a pipe\n'
assert lines(patty(str(fixture), 'read', 'str', '-', stdin=messy)) == [['0x0000000000000050', 'Hello World']]

# filter against the earlier value in column 2.
previous = '0x20\t1\n0x28\t64\n'
changed = patty(str(fixture), 'filter', 'u64', 'changed', '-', stdin=previous)
assert lines(changed) == [['0x0000000000000020', '64']], changed
assert '1 of 2 left' in changed.stderr, changed
none_left = patty(str(fixture), 'filter', 'u64', '==', '5', '-', stdin=previous)
assert none_left.returncode == 2 and none_left.stdout == '', none_left

# Text vs signature is decided by content; spaces survive the shell.
assert lines(patty(str(fixture), 'find', 'Hello World'))[0][0] == '0x0000000000000050'
assert lines(patty(str(fixture), 'find', '48 65 ?? 6C'))[0][0] == '0x0000000000000050'

# JSON Lines.
rows = [json.loads(line) for line in patty('--json', str(fixture), 'findval', '0x40', 'u64').stdout.splitlines()]
assert [row['address'] for row in rows] == ['0x0000000000000020', '0x0000000000000028'], rows

# check: name, status, value, rva; exit 2 because not everything is ok.
check = patty(str(fixture), 'check', str(profile))
assert check.returncode == 2, check
assert lines(check) == [['Hello', 'ok', '0x0000000000000050', '0x00000050'],
                        ['PointerTo40', 'ambiguous', '-', '-'],
                        ['Gone', 'missing', '-', '-']], check.stdout

# PATTY_TARGET, exit codes, help.
assert lines(patty('p', '0x50', env={'PATTY_TARGET': str(fixture)})) == [['0x0000000000000050', 'patty-smoke.bin+0x50 r-x']]
assert patty(str(fixture), 'find', 'DE AD BE EF').returncode == 2
unknown = patty(str(fixture), 'fnid', '00')
assert unknown.returncode == 1 and 'did you mean find' in unknown.stderr, unknown
assert patty('--help').returncode == 0
assert patty('--bogus').returncode == 1

# --table gives the human form in a pipe.
table = patty('--table', str(fixture), 'findval', '0x40', 'u64')
assert '$1' in table.stdout and '2 matches' in table.stdout, table

print('pipe-smoke-ok')
