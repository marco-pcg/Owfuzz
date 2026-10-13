#!/usr/bin/env python3
"""Exercise real PCAP output and extension discovery without radio hardware."""
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
binary = str(pathlib.Path(sys.argv[1]).resolve())
def run(*args, success=True):
    result = subprocess.run([binary, *args], capture_output=True)
    assert (result.returncode == 0) == success, (args, result.stderr)
    return result.stdout
assert b'ethernet' in run('--list-protocols')
args = ['--protocol', 'ethernet', '--frame', 'arp_request', '--strategy', 'bitflip', '--seed', '0', '--count', '5']
data = run(*args)
assert data == run(*args)
magic, major, minor, zone, sig, snap, link = struct.unpack('<IHHIIII', data[:24])
assert (magic, major, minor, snap, link) == (0xa1b2c3d4, 2, 4, 4096, 1)
pos = 24
for i in range(5):
    sec, usec, caplen, wirelen = struct.unpack('<IIII', data[pos:pos+16])
    assert (sec, usec, caplen, wirelen) == (0, i, 60, 60)
    pos += 16+caplen
assert pos == len(data)
ml = run('--protocol','802.11be','--frame','ml_probe_response')
assert struct.unpack('<I',ml[20:24])[0] == 105
assert ml[40+38:40+44] == bytes([255,10,107,0,0,7])
for extra in [['--seed','-1'],['--seed','4294967296'],['--count','0'],['--strategy','unknown'],['--source','xx:00:00:00:00:00'],['--bogus','x']]:
    run('--protocol','ethernet','--frame','arp_request',*extra,success=False)
run('--protocol','missing','--frame','arp_request',success=False)
run('--protocol','ethernet','--frame','missing',success=False)
run('--protocol','ethernet','--frame','arp_request','--interface','invalid',success=False)
run('--protocol','802.11be','--frame','ml_probe_response','--interface','invalid',success=False)
with tempfile.TemporaryDirectory() as tmp:
    output = pathlib.Path(tmp)/'corpus.pcap'
    assert run(*args,'--output',str(output)) == b''
    assert output.read_bytes() == data
    # A new module builds and runs with no core/CLI/Makefile edits.
    root = pathlib.Path(__file__).resolve().parent
    module = pathlib.Path(tmp)/'example.c'
    module.write_text('#include "protocol.h"\nstatic int build(struct ow_context *c, struct ow_packet *p) { (void)c; p->data[0]=42; p->len=1; return 0; }\nstatic const struct ow_frame frames[]={{65536,"example",build}};\nconst struct ow_family ow_module_example={"example",147,frames,1};\n')
    # Exercise the actual Makefile's automatic discovery and deletion handling.
    copy = pathlib.Path(tmp)/'checkout'
    copied_root = copy/'owfuzz/src/protocols'
    (copy/'tools').mkdir(parents=True)
    shutil.copy(root.parents[2]/'tools/generate_protocol_registry.py',copy/'tools')
    (copied_root/'modules').mkdir(parents=True)
    for name in ('protocol.c','protocol.h','cli.c','Makefile'):
        shutil.copy(root/name,copied_root/name)
    shutil.copy(module,copied_root/'modules/example.c')
    subprocess.run(['make','-s','-C',str(copied_root),'offline'],check=True)
    extended = copied_root/'build/owfuzz-protocol'
    result = subprocess.run([str(extended),'--protocol','example','--frame','example'],capture_output=True,check=True)
    assert result.stdout[-1]==42 and struct.unpack('<I',result.stdout[20:24])[0]==147
    # Removing a module must refresh the registry, including when no sources changed.
    shutil.copy(root/'modules/ethernet.c',copied_root/'modules/ethernet.c')
    (copied_root/'modules/example.c').unlink()
    subprocess.run(['make','-s','-C',str(copied_root),'offline'],check=True)
    listing = subprocess.check_output([str(extended),'--list-protocols'])
    assert b'ethernet' in listing and b'example' not in listing
print('CLI validation, PCAP encoding, reproducibility, and zero-core-edit extension passed')
