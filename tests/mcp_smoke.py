"""The MCP tools against the smoke fixture."""
import importlib.util
import os
import sys
from pathlib import Path

fixture = Path(sys.argv[1])
os.environ['PATTY_EXE'] = sys.argv[2]

spec = importlib.util.spec_from_file_location('patty_mcp', Path(__file__).resolve().parent.parent / 'mcp' / 'server.py')
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

hits = server.findval(str(fixture), '0x40', 'u64')
assert hits['exit'] == 0 and [h['address'] for h in hits['items']] == ['0x0000000000000020', '0x0000000000000028'], hits

text = server.find(str(fixture), 'Hello World')
assert text['items'][0]['value'] == '0x0000000000000050', text

value = server.read(str(fixture), 'str', '0x50')
assert value['items'][0]['value'] == 'Hello World', value

checked = server.check(str(fixture), str(fixture.with_name('patty-smoke.profile.json')))
assert checked['exit'] == 2 and [i['status'] for i in checked['items']] == ['ok', 'ambiguous', 'missing'], checked

anything = server.command(str(fixture), 'p [0x20]+0x10')
assert anything['items'][0]['value'] == '0x0000000000000050', anything

assert server.maps(str(fixture))['items'], 'no regions'
print('mcp-smoke-ok')
