"""Offline console and AD runtime regressions: no system configuration or probes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from test_safe_entrypoints import functions, run_bash

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / 'sysadmin.sh'


class OperationsConsole(unittest.TestCase):
    def console(self, code):
        return run_bash(['-c', 'source ./sysadmin.sh\n' + code])

    def test_missing_tool_is_skip(self):
        result = self.console('probe absent definitely_not_a_real_command; [[ $SKIPS == 1 && $FAILURES == 0 ]]')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('[SKIP]', result.stdout)

    def test_command_failure_and_timeout_are_not_success(self):
        for status in (1, 124, 137):
            result = self.console(f'timeout() {{ return {status}; }}; probe test uname; [[ $FAILURES == 1 ]]')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f'rc={status}', result.stderr)

    def test_no_timeout_means_no_probe_execution(self):
        result = self.console('''has() { [[ $1 != timeout ]]; }
            dangerous() { exit 99; }
            probe test dangerous; [[ $SKIPS == 1 && $FAILURES == 0 ]]''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_no_systemd_degrades_cleanly(self):
        result = self.console('systemd_host() { return 1; }; has() { return 1; }; services; logs; [[ $SKIPS == 3 ]]')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_tools_never_install_without_terminal(self):
        result = run_bash([str(CONSOLE), '--tools'])
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('terminal', result.stderr)

    def test_exit_status_reflects_failed_probes(self):
        result = self.console('inventory() { FAILURES=1; }; network() { :; }; storage() { :; }; services() { :; }; logs() { :; }; main --audit')
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

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
