"""Synthetic acceptance orchestration and fixture-redaction regressions."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('installer_acceptance', Path(__file__).with_name('verify_windows_installer.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)


class InstallerPhaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kerix-phase-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.install = self.root / 'installed'

    def test_app_failure_still_exercises_backend_and_uninstalls(self):
        order = []
        def app(*args):
            order.append('app')
            raise acceptance.AcceptanceFailure('Installed app activation/preload smoke failed.')
        with (patch.object(acceptance, 'check_app', side_effect=app),
              patch.object(acceptance, 'check_postgres_tools', side_effect=lambda *args: order.append('probes')),
              patch.object(acceptance, 'check_runtime', side_effect=lambda *args: order.append('backend')),
              patch.object(acceptance, 'uninstall_app', side_effect=lambda *args: order.append('uninstall')),
              redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): app$'):
                acceptance.check_installed(self.install, self.root)
        self.assertEqual(order, ['app', 'probes', 'backend', 'uninstall'])

    def test_backend_only_never_claims_app_acceptance(self):
        output = io.StringIO()
        with (patch.object(acceptance, 'check_app') as app,
              patch.object(acceptance, 'check_postgres_tools') as probes,
              patch.object(acceptance, 'check_runtime') as backend,
              patch.object(acceptance, 'uninstall_app') as uninstall, redirect_stdout(output)):
            acceptance.check_installed(self.install, self.root, skip_app=True)
        app.assert_not_called()
        backend.assert_called_once()
        probes.assert_called_once()
        uninstall.assert_called_once()
        self.assertIn('smoke SKIPPED', output.getvalue())
        self.assertNotIn('activation gate and preload passed', output.getvalue())

    def test_phase_failures_are_collected_and_fixture_credentials_are_redacted(self):
        password, signing = 'synthetic-private-password', 'synthetic-private-signing-value'
        def backend(_runtime, state):
            (state / 'secrets.json').write_text(json.dumps({'database_password': password, 'signing_key': signing}))
            (state / 'acceptance.log').write_text('RuntimeFailure at desktop_runtime.py:1:main\n' + signing + '\npostgresql://owner:' + password + '@local/db\n')
            raise ValueError(password)
        output = io.StringIO()
        with (patch.object(acceptance, 'check_app', side_effect=ValueError(signing)),
              patch.object(acceptance, 'check_postgres_tools'),
              patch.object(acceptance, 'check_runtime', side_effect=backend),
              patch.object(acceptance, 'uninstall_app', side_effect=RuntimeError(password)), redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): app, backend, uninstall$'):
                acceptance.check_installed(self.install, self.root)
        self.assertNotIn(password, output.getvalue())
        self.assertNotIn(signing, output.getvalue())
        self.assertNotIn('postgresql://', output.getvalue())
        self.assertIn('RuntimeFailure at', output.getvalue())

    def test_loader_probes_report_numeric_status_and_never_inherit_database_credentials(self):
        child = MagicMock()
        child.communicate.return_value = (b'fixed public tool output', b'')
        child.returncode = -1073741515
        output = io.StringIO()
        with (patch.object(acceptance.subprocess, 'Popen', return_value=child) as popen,
              patch.object(acceptance.subprocess, 'CREATE_NO_WINDOW', 0, create=True),
              patch.dict(os.environ, {'PGPASSWORD': 'synthetic-private-password', 'PATH': 'untrusted-ambient-path'}),
              redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'postgres-version, initdb-version, initdb-reject-auth'):
                acceptance.check_postgres_tools(self.install, self.root / 'probe')
        self.assertEqual(popen.call_count, 3)
        for call in popen.call_args_list:
            self.assertNotIn('PGPASSWORD', call.kwargs['env'])
            self.assertNotIn('untrusted-ambient-path', call.kwargs['env']['PATH'])
        command = popen.call_args_list[-1].args[0]
        self.assertIn('--auth-host=reject', command)
        self.assertIn('--auth-local=reject', command)
        self.assertIn('-1073741515 (0xC0000135)', output.getvalue())
        self.assertNotIn('synthetic-private-password', output.getvalue())

    def test_runtime_cleanup_records_windows_pipe_errors_without_raising(self):
        class Broken(io.BytesIO):
            def flush(self):
                raise OSError(22, 'synthetic-invalid-argument')
        child = MagicMock()
        child.poll.return_value = None
        child.stdin, child.stdout, child.stderr = Broken(), io.BytesIO(), io.BytesIO()
        child.wait.return_value = 1
        issues = acceptance.cleanup_runtime(child)
        self.assertTrue(any(value.startswith('stop-flush:OSError:errno=22') for value in issues))
        self.assertTrue(child.stdin.closed and child.stdout.closed and child.stderr.closed)

    def test_empty_and_missing_runtime_logs_are_reported_without_exposing_paths(self):
        state = self.root / 'workspace'
        state.mkdir()
        (state / 'acceptance.log').write_bytes(b'')
        report = acceptance.runtime_diagnostics(state)
        self.assertIn('acceptance.log: 0 bytes', report)
        self.assertIn('logs/database-initialize.log: unavailable', report)
        self.assertNotIn(str(self.root), report)


if __name__ == '__main__':
    unittest.main()
