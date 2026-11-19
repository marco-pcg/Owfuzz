#!/usr/bin/env python3
"""Record observed extension effort and paired comparisons; never infer coding time."""
import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import time
CORE = ('owfuzz/src/protocols/protocol.c', 'owfuzz/src/protocols/protocol.h',
        'owfuzz/src/protocols/cli.c', 'owfuzz/src/fuzz_control.c',
        'owfuzz/src/frames/frame.c', 'owfuzz/src/frames/frame.h',
        'owfuzz/src/common/config.c', 'owfuzz/src/Makefile', 'owfuzz/Makefile',
        'owfuzz/src/owfuzz.c')
def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()
def measure(base):
    tracked = git('diff', '--numstat', base, '--').splitlines()
    changes = []
    for row in tracked:
        added, deleted, name = row.split('\t', 2)
        changes.append({'path': name, 'added': None if added=='-' else int(added),
                        'deleted': None if deleted=='-' else int(deleted)})
    for name in git('ls-files', '--others', '--exclude-standard').splitlines():
        file = Path(name)
        changes.append({'path': name, 'added': len(file.read_bytes().splitlines()), 'deleted': 0})
    return {'changed_files': len(changes), 'core_files_changed': sum(c['path'] in CORE for c in changes),
            'added_lines': sum(c['added'] or 0 for c in changes),
            'deleted_lines': sum(c['deleted'] or 0 for c in changes), 'changes': changes}
def report(records):
    groups = {}
    pairs = {}
    for record in records:
        if record['variant'] not in ('baseline', 'refactored') or not math.isfinite(record['seconds']) or record['seconds'] <= 0:
            raise ValueError('Observations need a known variant and positive finite elapsed time')
        key = (record['participant'],record['task'],record['trial'])
        if record['variant'] in pairs.setdefault(key, {}):
            raise ValueError(f'Duplicate observation: {key}, {record["variant"]}')
        pairs[key][record['variant']] = record
        groups.setdefault(record['variant'],[]).append(record)
    summary = {variant: {'observations': len(rows),
                         'median_seconds': statistics.median(r['seconds'] for r in rows),
                         'median_core_files_changed': statistics.median(r['core_files_changed'] for r in rows)}
               for variant,rows in groups.items()}
    comparisons=[]
    for key, values in pairs.items():
        if 'baseline' not in values or 'refactored' not in values: continue
        before, after = values['baseline']['seconds'],values['refactored']['seconds']
        comparisons.append({'participant':key[0],'task':key[1],'trial':key[2],
                            'baseline_seconds':before,'refactored_seconds':after,
                            'time_reduction_percent':100*(before-after)/before})
    return {'groups':summary,'paired_comparisons':comparisons,
            'unpaired_observations':sum(len(v) for v in pairs.values() if len(v)!=2)}
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='command',required=True)
    start=sub.add_parser('start')
    start.add_argument('--variant',choices=['baseline','refactored'],required=True)
    start.add_argument('--task',required=True)
    start.add_argument('--participant',required=True)
    start.add_argument('--trial',type=int,default=1)
    start.add_argument('--base',default='HEAD')
    start.add_argument('--state',type=Path,required=True)
    finish=sub.add_parser('finish')
    finish.add_argument('--state',type=Path,required=True)
    finish.add_argument('--results',type=Path,required=True)
    finish.add_argument('--validation',required=True,help='Checks actually run and their results')
    summary=sub.add_parser('report')
    summary.add_argument('results',type=Path)
    args=parser.parse_args()
    if args.command=='start':
        args.state = args.state.resolve()
        root = Path(git('rev-parse','--show-toplevel'))
        if args.state.is_relative_to(root): parser.error('Store trial state outside the checkout')
        if args.trial < 1: parser.error('Trial number must be positive')
        os.chdir(root)
        baseline=git('rev-parse',args.base+'^{commit}')
        if git('status','--porcelain'):
            parser.error('Start each trial from a clean checkout; store state/results outside the repository')
        state={'variant':args.variant,'task':args.task,'participant':args.participant,'trial':args.trial,
               'base':baseline,'repository':str(root),
               'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'started_at':dt.datetime.now(dt.timezone.utc).isoformat(),
               'monotonic_start':time.monotonic()}
        with args.state.open('x') as fp: json.dump(state,fp,indent=2)
        print('Trial started; finish after implementation and validation.')
    elif args.command=='finish':
        args.state = args.state.resolve()
        args.results = args.results.resolve()
        record=json.loads(args.state.read_text())
        root = Path(record['repository'])
        if args.results.is_relative_to(root): parser.error('Store study results outside the checkout')
        if record['boot_id'] != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            parser.error('System restarted during trial; restart this observation')
        os.chdir(root)
        record['seconds']=time.monotonic()-record.pop('monotonic_start')
        if record['seconds']<=0: parser.error('Invalid timer; restart the trial (do not reboot during a trial)')
        record.update(measure(record['base']))
        record['validation']=args.validation
        record['finished_at']=dt.datetime.now(dt.timezone.utc).isoformat()
        with args.results.open('a') as fp: fp.write(json.dumps(record)+'\n')
        args.state.unlink()
        print(json.dumps(record,indent=2))
    else:
        records=[json.loads(row) for row in args.results.read_text().splitlines() if row.strip()]
        print(json.dumps(report(records),indent=2))
if __name__=='__main__': main()
