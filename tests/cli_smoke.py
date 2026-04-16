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
assert value['schema_version'] == 1, value
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
assert probe['schema_version'] == 1, probe
assert probe['command'] == 'probe', probe
assert probe['probed_size'] == 32, probe

regions = run('list', '--file', str(fixture), '--output', 'json')
assert regions['schema_version'] == 1, regions
assert regions['command'] == 'list', regions
assert regions['regions'], regions

print('cli-smoke-ok')
