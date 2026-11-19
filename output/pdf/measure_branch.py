"""Reproduce paper metrics from tracked Git blobs; excludes generated code and tests."""
import subprocess,json,importlib.metadata
from pathlib import Path
import lizard
ROOT=Path(__file__).resolve()
BASE='10af304'; AFTER='e98b03e'
def git(*a): return subprocess.check_output(['git',*a],text=True)
def source_paths(ref):
    paths=git('ls-tree','-r','--name-only',ref,'owfuzz/src').splitlines()
    return [p for p in paths if p.endswith('.c') and '/hostapd_lib/' not in p and '/tests/' not in p and '/fixtures/' not in p and '/test_' not in p and not p.endswith('/generated_registry.c')]
def measure(ref):
    functions=[]; files=[]
    for path in source_paths(ref):
        source=git('show',ref+':'+path)
        info=lizard.analyze_file.analyze_source_code(path,source)
        files.append(dict(path=path,nloc=info.nloc,physical_lines=len(source.splitlines())))
        for f in info.function_list:
            functions.append(dict(file=path,name=f.name,nloc=f.nloc,ccn=f.cyclomatic_complexity))
    return dict(commit=git('rev-parse',ref).strip(),files=files,functions=functions,
        summary=dict(c_files=len(files),functions=len(functions),file_nloc=sum(f['nloc'] for f in files),
                     summed_function_ccn=sum(f['ccn'] for f in functions)))
result={'analyzer':'Lizard '+importlib.metadata.version('lizard'),'scope':'Tracked production C under owfuzz/src; excludes hostapd_lib, tests, protocol test files, fixtures and generated registry. Includes relocated adapters and protocol core. Excludes linux_wifi backends and Python tooling.',
        'baseline':measure(BASE),'refactored':measure(AFTER)}
Path('output/pdf').mkdir(parents=True, exist_ok=True)
Path('output/pdf/owfuzz-branch-metrics.json').write_text(json.dumps(result,indent=2)+'\n')
for variant in ['baseline','refactored']:
 print(variant,result[variant]['summary'])
 for f in result[variant]['functions']:
  if f['name'] in {'ow_wifi_find_id','ow_wifi_find_name','owfuzz_config_get_frames','ow_register','ow_find_family','ow_find_frame','ow_generate','ow_deliver'}: print(f['name'],f['nloc'],f['ccn'])
