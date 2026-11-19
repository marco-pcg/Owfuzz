#!/usr/bin/env python3
"""Generate portable module registration. Each file exports ow_module_<stem>."""
import argparse
from pathlib import Path
import re
parser = argparse.ArgumentParser()
parser.add_argument('output', type=Path)
parser.add_argument('modules', nargs='+', type=Path)
args = parser.parse_args()
lines = ['/* Generated; do not edit. */', '#include "protocol.h"']
names = []
for module in sorted(args.modules):
    name = module.stem
    if not re.fullmatch(r'[a-z][a-z0-9_]*', name):
        parser.error(f'Invalid module filename: {module}')
    names.append(name)
    qualifier = '' if name == 'wifi_legacy' else 'const '
    lines.append(f'extern {qualifier}struct ow_family ow_module_{name};')
if 'wifi_legacy' in names:
    lines.append('extern int ow_prepare_wifi_legacy(void);')
lines.append('int ow_register_modules(struct ow_registry *r) {')
if 'wifi_legacy' in names:
    lines.append('    if (ow_prepare_wifi_legacy()) return -1;')
for name in names:
    lines.append(f'    if (ow_register(r, &ow_module_{name})) return -1;')
lines += ['    return 0;', '}']
args.output.parent.mkdir(parents=True, exist_ok=True)
content = '\n'.join(lines) + '\n'
if not args.output.exists() or args.output.read_text() != content:
    args.output.write_text(content)
