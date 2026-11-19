#!/usr/bin/env python3
"""Compare every migrated legacy adapter against frozen pre-refactor dispatch."""
from pathlib import Path
import re
import subprocess
import tempfile
root = Path(__file__).resolve().parent
src = root.parent
registry = (src/'frames/legacy_registry.c').read_text()
functions = sorted(set(re.findall(r'\b(create_\w+|save_\w+_state|load_\w+_state)\(', registry)))
# Callback names in table initializers have no parentheses.
functions += sorted(set(re.findall(r'\b(?:save|load)_\w+_state\b',registry))-set(functions))
headers='\n'.join(p.read_text() for p in (src/'frames').rglob('*.h'))
headers = re.sub(r'/\*.*?\*/', '', headers, flags=re.S)
headers = re.sub(r'//[^\n]*', '', headers)
stubs=['#include "legacy_registry.h"', '#include "../common/config.h"', 'void fuzz_logger_log(int level, const char *fmt, ...) { (void)level; (void)fmt; }', 'fuzzing_option fuzzing_opt = {0};']
for index,name in enumerate(functions):
    if name.startswith(('save_', 'load_')):
        stubs.append(f'void {name}(void) {{}}')
        continue
    match=re.search(r'struct packet\s+'+name+r'\s*\((.*?)\)\s*;',headers,re.S)
    assert match, name
    params=match.group(1)
    body=['struct packet p = {0};',f'p.data[p.len++] = {index};']
    for param in params.split(','):
        arg=re.search(r'(\w+)\s*$',param.strip()).group(1)
        body.append(f'memcpy(p.data+p.len, &{arg}, sizeof({arg})); p.len += sizeof({arg});')
    body.append('return p;')
    stubs.append(f'struct packet {name}({params}) {{'+''.join(body)+'}')
driver='''
#include <assert.h>
struct packet baseline_get_frame(uint8_t, struct ether_addr, struct ether_addr, struct ether_addr, struct packet *);
int main(int argc, char **argv) {
    struct ether_addr b={{1,2,3,4,5,6}}, s={{7,8,9,10,11,12}}, d={{13,14,15,16,17,18}};
    struct packet received={0}, a, bpacket;
    size_t i; int variant;
    assert(ow_wifi_frame_count==42);
    received.len=sizeof(struct ieee_hdr)+8; received.channel=44;
    for(i=0;i<ow_wifi_frame_count;i++) {
        const struct ow_wifi_frame *f=&ow_wifi_frames[i];
        assert(ow_wifi_find_name(f->name)==f && ow_wifi_find_id(f->id)==f);
        assert(!strcmp(return_frame_type(f->id),f->symbol));
        for(variant=0;variant<2;variant++) {
            struct packet *r=variant ? &received : NULL;
            a=baseline_get_frame(f->id,b,s,d,r);
            bpacket=get_frame(f->id,b,s,d,r);
            assert(a.len==bpacket.len && !memcmp(a.data,bpacket.data,a.len));
            assert(fuzzing_opt.current_frame==f->id);
        }
    }
    assert(!ow_wifi_find_name("missing"));
    a=get_frame(255,b,s,d,NULL); assert(a.len==0);
    received.len=1;
    a=get_frame(IEEE80211_TYPE_PROBERES,b,s,d,&received); assert(a.len>0);
    save_fuzzing_state(); load_fuzzing_state();
    assert(argc==4);
    {
        uint8_t frames[64]={0}; uint32_t count=0;
        assert(!owfuzz_config_get_ap_frames(argv[1],frames,&count) && count==42);
        for(i=0;i<42;i++) assert(frames[i]==ow_wifi_frames[i].id);
        assert(!owfuzz_config_get_sta_frames(argv[1],frames,&count) && count==1 && frames[0]==IEEE80211_TYPE_ACK);
        assert(owfuzz_config_get_ap_frames(argv[2],frames,&count)==-1 && count==0);
        assert(owfuzz_config_get_ap_frames(argv[3],frames,&count)==-1 && count==0);
    }
    return 0;
}
'''
# return_frame_type is historically undeclared in frame.h.
stubs.insert(1,'const char *return_frame_type(uint8_t);')
with tempfile.TemporaryDirectory() as tmp:
    test=Path(tmp)/'test.c'; binary=Path(tmp)/'test'
    test.write_text('\n'.join(stubs)+driver)
    command=['cc','-std=gnu99','-ffunction-sections','-fdata-sections','-Wl,--gc-sections',
             '-Wno-unused-variable','-Wno-unused-parameter','-I'+str(src/'frames'),
             '-I'+str(src/'hostapd_lib'),'-I'+str(src/'hostapd_lib/utils'),
             '-I'+str(src.parent/'linux_wifi/trans'),str(test),
             str(root/'fixtures/legacy_frame.c'),str(src/'frames/frame.c'),
             str(src/'frames/legacy_registry.c'),str(src/'common/config.c'),'-o',str(binary)]
    subprocess.run(command,check=True)
    names=re.findall(r'\{IEEE80211_TYPE_\w+, "([^"]+)"',registry)
    config=Path(tmp)/'valid.cfg'; unknown=Path(tmp)/'unknown.cfg'; overflow=Path(tmp)/'overflow.cfg'
    config.write_text('[ap-frames]\n'+''.join(name+'=1\n' for name in names)+'[sta-frames]\nack=1\n')
    unknown.write_text('[ap-frames]\nmissing=1\n')
    overflow.write_text('[ap-frames]\n'+'ack=1\n'*65)
    subprocess.run([str(binary),str(config),str(unknown),str(overflow)],check=True)
print('All 42 legacy adapters match frozen dispatch for absent/present received packets')
