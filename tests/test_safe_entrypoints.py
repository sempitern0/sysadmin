"""Exercise launch paths and pure validators, never administrative modes."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted(ROOT.glob('*.sh'))


def run_bash(args, *, code=None):
    with tempfile.TemporaryDirectory() as home:
        env = dict(os.environ, HOME=home, NO_COLOR='1', TERM='dumb')
        return subprocess.run(['bash', *args], input=code, text=True,
                              capture_output=True, cwd=ROOT, env=env,
                              start_new_session=True,
                              timeout=15)


def functions(file, *names):
    source = (ROOT / file).read_text()
    result = []
    for name in names:
        match = re.search(r'^' + re.escape(name) + r'\(\) \{\n.*?^\}', source, re.M | re.S)
        if not match:
            raise AssertionError(f'Missing pure function: {file}:{name}')
        result.append(match.group())
    return '\n'.join(result)


class EntryPoints(unittest.TestCase):
    def test_help_and_invalid_arguments_without_runtime(self):
        for script in SCRIPTS:
            for args, status in [(['--help'], 0), (['--not-a-mode'], 2),
                                 (['--lang'], 2), (['--lang', 'xx'], 2)]:
                with self.subTest(script=script.name, args=args):
                    result = run_bash([str(script), *args])
                    self.assertEqual(result.returncode, status, result.stdout + result.stderr)
                    self.assertNotIn('unbound variable', result.stderr)

    def test_preflight_without_elevation_or_terminal(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                result = run_bash([str(script), '--preflight'])
                self.assertIn(result.returncode, (0, 1), result.stderr)
                self.assertIn('No changes made.', result.stdout)
                self.assertNotIn('Permission denied', result.stderr)
                self.assertNotIn('unbound variable', result.stderr)

    def test_interactive_requires_terminal_before_runtime(self):
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                result = run_bash([str(script), '--manage'])
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stdout + result.stderr, r'TTY|terminal')
                self.assertNotIn('Permission denied', result.stderr)

    def test_ipv4_and_cidr_boundaries(self):
        for file, validator, cidr in [
            ('debian-ad-assistant.sh', 'is_valid_ipv4', 'is_valid_cidr'),
            ('rhel-ad-assistant.sh', 'valid_ipv4', 'valid_cidr'),
            ('linux-ad-client-assistant.sh', 'valid_ip', None),
            ('rhel-ad-client-assistant.sh', 'valid_ip', None),
        ]:
            names = [validator] + ([cidr] if cidr else [])
            script = 'set -uo pipefail\n' + functions(file, *names) + '\n'
            for address in ('0.0.0.0', '255.255.255.255', '192.168.1.8', '08.008.8.8'):
                script += f'{validator} "{address}" || exit 10\n'
            for address in ('1.2.3.4.', '1.2.3', '1.2.3.256', '1.2.3.4/24', '1.2.3.4\\n5', '-1.2.3.4'):
                script += f'if {validator} "{address}"; then exit 11; fi\n'
            if cidr:
                for prefix in ('0', '8', '08', '24', '32'):
                    script += f'{cidr} "10.0.0.0/{prefix}" || exit 12\n'
                for prefix in ('33', '-1', '256', '999999999999999999999999999999', 'x'):
                    script += f'if {cidr} "10.0.0.0/{prefix}"; then exit 13; fi\n'
            result = run_bash(['-s'], code=script)
            self.assertEqual(result.returncode, 0, file + result.stderr)

    def test_guarded_ips_rejects_invalid_and_local_addresses(self):
        for file, validator, candidate in [
            ('rhel-ad-assistant.sh', 'valid_ipv4', 'defense_public_ipv4'),
            ('linux-ad-client-assistant.sh', 'valid_ip', 'security_is_public_ipv4'),
            ('rhel-ad-client-assistant.sh', 'valid_ip', 'security_is_public_ipv4'),
        ]:
            script = 'set -uo pipefail\n' + functions(file, validator, candidate) + '\n'
            for ip in ('10.0.0.1', '172.16.2.1', '192.168.1.1', '127.0.0.1', '169.254.0.1', '0.0.0.0', '225.0.0.1', '8.8.999.999'):
                script += f'if {candidate} {ip}; then exit 20; fi\n'
            script += f'{candidate} 8.8.8.8 || exit 21\n{candidate} 08.008.8.8 || exit 22\n'
            result = run_bash(['-s'], code=script)
            self.assertEqual(result.returncode, 0, file + result.stderr)

    def test_non_bash_launch_fails_with_guidance(self):
        # `sh script.sh` (dash/busybox) must stop before Bash-only syntax runs.
        sh = shutil.which('sh')
        if not sh or subprocess.run([sh, '-c', 'printf %s "${BASH_VERSION:-}"'],
                                    capture_output=True, text=True).stdout:
            self.skipTest('sh is unavailable or is Bash')
        for script in SCRIPTS:
            with self.subTest(script=script.name):
                result = subprocess.run([sh, str(script), '--help'], text=True,
                                        capture_output=True, cwd=ROOT, timeout=15)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('requires Bash 4+', result.stderr)
                self.assertNotIn('Illegal option', result.stderr)

    def test_local_values_are_assigned_before_reuse(self):
        # Regression for SC2318: callers below deliberately have no variable
        # named like the callee's first local, so dynamic scoping cannot mask it.
        with tempfile.TemporaryDirectory() as work:
            snap = Path(work, 'snap')
            snap.mkdir()
            (snap / 'snapshot.env').write_text('')
            source = Path(work, 'etc-hosts')
            source.write_text('fixture\n')
            target = Path(work, 'out', 'config.env')
            target.parent.mkdir()
            client = functions('linux-ad-client-assistant.sh', 'record_assistant_package')
            server = functions('rhel-ad-assistant.sh', 'atomic_write', 'snapshot_file')
            script = f'''set -euo pipefail
{client}
{server}
cd /
record_assistant_package {snap} realmd
grep -qx realmd {snap}/packages-installed-by-assistant.txt || exit 20
printf 'A=1\\n' | atomic_write {target}
grep -qx A=1 {target} || exit 21
: >{snap}/files.tsv
snapshot_file {snap} {source}
key="$(cut -f3 {snap}/files.tsv)"
[[ -n "$key" && -f "{snap}/files/$key" ]] || exit 22
'''
            result = run_bash(['-s'], code=script)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list(Path(work, 'out').iterdir()), [target])
            self.assertFalse(Path('/packages-installed-by-assistant.txt').exists())


if __name__ == '__main__':
    unittest.main()
