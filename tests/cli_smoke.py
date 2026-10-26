import json
import subprocess
import sys
from pathlib import Path

fixture = Path(sys.argv[1])
exe = Path(sys.argv[2])

def run(*args):
    result = subprocess.run([str(exe), *args], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)

value = run('scan-value', '--file', str(fixture), '--value', '0xC0FFEE', '--size', '3', '--output', 'json')
assert value['schema_version'] == 2, value
assert value['command'] == 'scan-value', value
assert value['results'][0]['count'] == 1, value

pointer = run('scan-pointer', '--file', str(fixture), '--address', '0x40', '--output', 'json')
assert pointer['command'] == 'scan-pointer', pointer
assert pointer['results'][0]['count'] == 2, pointer

pointers = run('scan-pointers', '--file', str(fixture), '--address', '0x40', '--address', '0x1234', '--output', 'json')
assert pointers['command'] == 'scan-pointers', pointers
assert len(pointers['results']) == 2, pointers
assert pointers['results'][0]['count'] == 2, pointers

probe = run('probe', '--file', str(fixture), '--address', '0x0', '--size', '32', '--output', 'json')
assert probe['schema_version'] == 2, probe
assert probe['command'] == 'probe', probe
assert probe['probed_size'] == 32, probe

regions = run('list', '--file', str(fixture), '--output', 'json')
assert regions['schema_version'] == 2, regions
assert regions['command'] == 'list', regions
assert regions['regions'], regions

# check: one ok, one ambiguous, one missing -> exit 2; profile module is ignored for files
profile = fixture.with_name('patty-smoke.profile.json')
proc = subprocess.run([str(exe), 'check', '--file', str(fixture), '--profile', str(profile), '--output', 'json'],
                      capture_output=True, text=True)
assert proc.returncode == 2, proc
check = json.loads(proc.stdout)
assert check['command'] == 'check', check
assert {p['name']: p['status'] for p in check['patterns']} == {
    'Hello': 'ok', 'PointerTo40': 'ambiguous', 'Gone': 'missing'}, check
assert check['patterns'][0]['rva'] == '0x00000050', check
assert check['summary'] == {'ok': 1, 'ambiguous': 1, 'missing': 1, 'unresolved': 0}, check

print('cli-smoke-ok')
