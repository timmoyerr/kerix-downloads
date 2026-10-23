"""Synthetic acceptance orchestration and fixture-redaction regressions."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
              patch.object(acceptance, 'check_runtime', side_effect=lambda *args: order.append('backend')),
              patch.object(acceptance, 'uninstall_app', side_effect=lambda *args: order.append('uninstall')),
              redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): app$'):
                acceptance.check_installed(self.install, self.root)
        self.assertEqual(order, ['app', 'backend', 'uninstall'])

    def test_backend_only_never_claims_app_acceptance(self):
        output = io.StringIO()
        with (patch.object(acceptance, 'check_app') as app,
              patch.object(acceptance, 'check_runtime') as backend,
              patch.object(acceptance, 'uninstall_app') as uninstall, redirect_stdout(output)):
            acceptance.check_installed(self.install, self.root, skip_app=True)
        app.assert_not_called()
        backend.assert_called_once()
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
              patch.object(acceptance, 'check_runtime', side_effect=backend),
              patch.object(acceptance, 'uninstall_app', side_effect=RuntimeError(password)), redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): app, backend, uninstall$'):
                acceptance.check_installed(self.install, self.root)
        self.assertNotIn(password, output.getvalue())
        self.assertNotIn(signing, output.getvalue())
        self.assertNotIn('postgresql://', output.getvalue())
        self.assertIn('RuntimeFailure at', output.getvalue())


if __name__ == '__main__':
    unittest.main()
