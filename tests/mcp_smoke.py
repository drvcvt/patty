import importlib.util
import json
import os
import sys
from pathlib import Path

fixture = Path(sys.argv[1])
patty_exe = Path(sys.argv[2])
os.environ['PATTY_EXE'] = str(patty_exe)

spec = importlib.util.spec_from_file_location('patty_mcp', Path('mcp/server.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

value = json.loads(module.scan_value(value='0xC0FFEE', value_size=3, file_path=str(fixture)))
assert value['results'][0]['count'] == 1, value

pointer = json.loads(module.scan_pointer(target='0x40', file_path=str(fixture)))
assert pointer['results'][0]['count'] == 2, pointer

pointers32 = json.loads(module.scan_pointers(targets=['0x1234'], file_path=str(fixture), pointer_size=4))
assert pointers32['results'][0]['count'] == 1, pointers32

probe = json.loads(module.probe_object(address='0x0', file_path=str(fixture), max_size=0x20))
assert probe['probed_size'] == 32, probe

regions = json.loads(module.list_regions(file_path=str(fixture)))
assert isinstance(regions, list) and regions, regions
print('mcp-smoke-ok')
