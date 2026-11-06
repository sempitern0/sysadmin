#!/usr/bin/env python3
"""Offline validation: never execute administrative modes or install dependencies."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-shellcheck', action='store_true', help='fail if ShellCheck is unavailable')
    parser.add_argument('--require-powershell', action='store_true', help='fail if PowerShell is unavailable')
    args = parser.parse_args()
    commands = [[sys.executable, 'tools/sync_linux_clients.py', '--check']]
    missing = []
    if shutil.which('bash'):
        commands += [['bash', '-n', str(p.relative_to(ROOT))] for p in sorted(ROOT.glob('*.sh'))]
        commands += [[sys.executable, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_*.py', '-v']]
    else:
        missing.append('bash (required; use tools/verify_powershell.ps1 on Windows)')
    if shutil.which('shellcheck'):
        commands += [['shellcheck', '--severity=error', *[p.name for p in sorted(ROOT.glob('*.sh'))]]]
        # Warning-level rules that have caused real defects here. SC2318: a value
        # used in the same `local` statement is expanded before `local` assigns it,
        # e.g. `local snap="$1" meta="${snap}/x"` yields "/x".
        commands += [['shellcheck', '--severity=warning', '--include=SC2318',
                      *[p.name for p in sorted(ROOT.glob('*.sh'))]]]
    elif args.require_shellcheck:
        missing.append('shellcheck')
    else:
        print('SKIP ShellCheck: unavailable (CI requires it).')
    powershell = shutil.which('pwsh') or shutil.which('powershell')
    if powershell:
        commands += [[powershell, '-NoProfile', '-NonInteractive', '-File', 'tools/verify_powershell.ps1']]
    elif args.require_powershell:
        missing.append('PowerShell')
    else:
        print('SKIP PowerShell: unavailable (CI tests both Windows engines).')
    failures = []
    for command in commands:
        print('+ ' + ' '.join(command), flush=True)
        try:
            status = subprocess.run(command, cwd=ROOT, check=False, timeout=180).returncode
        except subprocess.TimeoutExpired:
            status = 1
            print('FAIL: check timed out.', file=sys.stderr)
        if status:
            failures.append(command)
    for tool in missing:
        print('Missing required tool: ' + tool, file=sys.stderr)
    print(f'{len(commands) - len(failures)}/{len(commands)} checks passed; {len(missing)} missing required tools.')
    return int(bool(failures or missing))


if __name__ == '__main__':
    raise SystemExit(main())
