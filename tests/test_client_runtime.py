"""Standalone AD client runtime regressions; no system configuration or probes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_safe_entrypoints import functions

ROOT = Path(__file__).resolve().parents[1]


class ClientRuntime(unittest.TestCase):
    def test_single_download_launches_without_repository(self):
        for original in sorted(ROOT.glob('*.sh')):
            with self.subTest(script=original.name), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / original.name
                script.write_bytes(original.read_bytes())
                for option in ('--help', '--preflight'):
                    result = subprocess.run(['bash', str(script), option], cwd=directory,
                                            env=dict(os.environ, HOME=directory),
                                            capture_output=True, text=True, timeout=15,
                                            start_new_session=True)
                    self.assertIn(result.returncode, (0,) if option == '--help' else (0, 1),
                                  result.stdout + result.stderr)
                    if option == '--preflight':
                        self.assertIn('No changes made.', result.stdout)
                self.assertEqual(list(Path(directory).iterdir()), [script])

    def test_invalid_timeout_environment_before_runtime(self):
        for script in ('linux-ad-client-assistant.sh', 'rhel-ad-client-assistant.sh'):
            for name in ('AD_CLIENT_NETWORK_TIMEOUT', 'AD_CLIENT_MEMBERSHIP_TIMEOUT', 'AD_CLIENT_SLOW_NETWORK_TIMEOUT'):
                for value in ('0', '-1', '08', '3601', '99999999999999', 'x', 'a[$(false)]'):
                    with self.subTest(script=script, name=name, value=value):
                        result = subprocess.run(['bash', str(ROOT / script), '--preflight'],
                                                env=dict(os.environ, **{name: value}), text=True,
                                                capture_output=True, timeout=5, start_new_session=True)
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertIn('integer seconds', result.stderr)

    def test_client_lock_excludes_second_process_and_releases(self):
        body = functions('linux-ad-client-assistant.sh', 'acquire_runtime_lock')
        with tempfile.TemporaryDirectory() as state:
            code = body + '\nSTATE_ROOT=$1\nacquire_runtime_lock || exit 1\n'
            first = subprocess.Popen(['bash', '-c', code + 'echo ready; read -r _', '_', state],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(first.stdout.readline().strip(), 'ready')
                blocked = subprocess.run(['bash', '-c', code, '_', state], capture_output=True, text=True, timeout=5)
                self.assertEqual(blocked.returncode, 1)
                self.assertIn('Another AD client', blocked.stderr)
            finally:
                first.communicate('\n', timeout=5)
            released = subprocess.run(['bash', '-c', code, '_', state], capture_output=True, text=True, timeout=5)
            self.assertEqual(released.returncode, 0, released.stderr)


if __name__ == '__main__':
    unittest.main()
