#!/usr/bin/env python3
"""Offline smoke checks against the fully linked executable and real legacy builders."""
import pathlib
import struct
import subprocess
import sys
binary=str(pathlib.Path(sys.argv[1]).resolve())
listing=subprocess.check_output([binary,'--list-protocols'],text=True)
legacy=next(line.split(':',1)[1].split() for line in listing.splitlines() if line.startswith('802.11 ('))
assert len(legacy)==42
for name in legacy:
    result=subprocess.run([binary,'--protocol','802.11','--frame',name,'--seed','42'],capture_output=True,timeout=5)
    if name=='control_frame_extension':
        assert result.returncode!=0 and b'Campaign failed' in result.stderr
        continue
    assert result.returncode==0, (name,result.stderr)
    assert len(result.stdout)>=40 and struct.unpack('<I',result.stdout[:4])[0]==0xa1b2c3d4, name
    caplen=struct.unpack('<I',result.stdout[32:36])[0]
    assert caplen>0 and len(result.stdout)==40+caplen, name
for family,frame in [('ethernet','arp_request'),('802.11be','ml_probe_response')]:
    cmd=[binary,'--protocol',family,'--frame',frame,'--strategy','bitflip','--seed','42','--count','10']
    assert subprocess.check_output(cmd)==subprocess.check_output(cmd), family
print('Full executable: 41 real legacy builders, known empty stub, and reproducible new-family campaigns passed')
