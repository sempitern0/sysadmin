"""Real rclone protocol tests on loopback only; disposable data, no real credentials."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PWSH = shutil.which('pwsh')
RCLONE = shutil.which('rclone')


@unittest.skipUnless(PWSH and RCLONE, 'requires pwsh and rclone for loopback transport tests')
class MigrationTransport(unittest.TestCase):
    def run_assistant(self, *args, success=True):
        result = subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-File',
                                 str(ROOT / 'migration-assistant.ps1'), *args],
                                text=True, capture_output=True, timeout=30)
        details = result.stdout + result.stderr
        if (result.returncode == 0) != success and '-Workspace' in args:
            job = Path(args[args.index('-Workspace') + 1])
            details += '\n'.join(p.read_text(errors='replace') for p in job.glob('*.log'))
        self.assertEqual(result.returncode == 0, success, details)
        return result

    def test_webdav_and_sftp_copy_verify_conflicts_and_retry(self):
        for backend, profile in [('webdav', 'NextcloudFiles'), ('sftp', 'UbuntuFiles')]:
            with self.subTest(backend=backend), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                source = base / 'source [pilot]'
                source.mkdir()
                (source / 'test data.txt').write_text('original content', encoding='utf-8')
                (source / 'empty').mkdir()
                target = base / 'target'
                target.mkdir()
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                # Public loopback-only, disposable fixture, not a deployment recipe.
                args = [RCLONE, 'serve', backend, str(target), '--addr', f'127.0.0.1:{port}', '--dir-cache-time', '0s']
                if backend == 'sftp':
                    args += ['--user', 'fixture', '--pass', 'fixture-only']
                server = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    for _ in range(100):
                        if server.poll() is not None:
                            self.fail('Loopback fixture exited')
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            time.sleep(.05)
                    else:
                        self.fail('Loopback fixture not ready')
                    config = base / 'rclone.conf'
                    if backend == 'webdav':
                        config.write_text(f'[fixture]\ntype = webdav\nurl = http://127.0.0.1:{port}/\nvendor = other\n')
                    else:
                        password = subprocess.check_output([RCLONE, 'obscure', 'fixture-only'], text=True).strip()
                        config.write_text(f'[fixture]\ntype = sftp\nhost = 127.0.0.1\nport = {port}\nuser = fixture\npass = {password}\ndisable_hashcheck = true\n')
                    job = base / 'job'
                    self.run_assistant('-Mode', 'Plan', '-Profile', profile, '-Source', str(source),
                                       '-Destination', 'fixture:batch', '-ConfigPath', str(config), '-Workspace', str(job))
                    common = ['-Workspace', str(job)]
                    self.run_assistant('-Mode', 'Copy', *common, success=False)
                    self.assertFalse((target / 'batch').exists())
                    self.run_assistant('-Mode', 'DryRun', *common)
                    self.assertFalse((target / 'batch').exists())
                    attest = ['-BackupVerified', '-PermissionsReviewed', '-SourceFrozen', '-ConfirmDestination', 'fixture:batch']
                    self.run_assistant('-Mode', 'Copy', *common, *attest)
                    self.run_assistant('-Mode', 'Verify', *common, '-SourceFrozen')
                    self.assertEqual(json.loads((job / 'plan.json').read_text())['Phase'], 'ContentVerified')
                    self.assertEqual((target / 'batch' / 'test data.txt').read_text(), 'original content')
                    # Corruption of equal size must be caught by download comparison.
                    (target / 'batch' / 'test data.txt').write_text('corrupt! content')
                    self.run_assistant('-Mode', 'Verify', *common, '-SourceFrozen', success=False)
                    self.assertEqual(json.loads((job / 'plan.json').read_text())['Phase'], 'Failed')
                    # Size-changing conflict must not be overwritten by immutable copy.
                    (source / 'test data.txt').write_text('source changed to a different length')
                    self.run_assistant('-Mode', 'DryRun', *common, success=False)
                    self.assertEqual((target / 'batch' / 'test data.txt').read_text(), 'corrupt! content')
                    # A conflict arising AFTER preview must also block the actual copy.
                    (source / 'test data.txt').write_text('original content')
                    (target / 'batch' / 'test data.txt').write_text('original content')
                    self.run_assistant('-Mode', 'DryRun', *common)
                    (target / 'batch' / 'test data.txt').write_text('a new conflicting destination file')
                    self.run_assistant('-Mode', 'Copy', *common, *attest, success=False)
                    self.assertEqual((target / 'batch' / 'test data.txt').read_text(), 'a new conflicting destination file')
                    # Operator restores fixture baseline; same workspace can recover.
                    (source / 'test data.txt').write_text('original content')
                    (target / 'batch' / 'test data.txt').write_text('original content')
                    self.run_assistant('-Mode', 'DryRun', *common)
                    self.run_assistant('-Mode', 'Copy', *common, *attest)
                    self.run_assistant('-Mode', 'Verify', *common, '-SourceFrozen')
                    self.assertEqual(json.loads((job / 'plan.json').read_text())['Phase'], 'ContentVerified')
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
