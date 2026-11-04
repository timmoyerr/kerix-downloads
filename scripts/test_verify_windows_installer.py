"""Synthetic acceptance orchestration and fixture-redaction regressions."""
from contextlib import redirect_stdout
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import stat
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from zipfile import ZipFile, ZipInfo

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

    def test_probe_archive_refuses_traversal_absolute_paths_and_symlinks(self):
        for name, linked in [('../outside', False), ('/absolute', False), ('postgres/../../outside', False),
                             ('postgres/bin/linked', True), ('postgres/bin/tool.exe:stream', False)]:
            with self.subTest(name=name):
                archive = self.root / 'probe.zip'
                with ZipFile(archive, 'w') as source:
                    entry = ZipInfo(name)
                    entry.external_attr = ((stat.S_IFLNK if linked else stat.S_IFREG) | 0o644) << 16
                    source.writestr(entry, b'not executable')
                with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'Unsafe PostgreSQL probe ZIP'):
                    acceptance.extract_probe(archive, self.root / 'payload')
                self.assertFalse((self.root / 'payload').exists())
                self.assertFalse((self.root / 'outside').exists())

    def test_system_import_diagnostic_uses_only_system32_and_reports_missing_exports(self):
        import ctypes
        runtime = self.root / 'runtime'
        binary = runtime / 'postgres/bin/postgres.exe'
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'not executed')
        import hashlib
        manifest = self.root / 'system-imports.json'
        manifest.write_text(json.dumps({'schemaVersion': 1, 'binaries': {'postgres.exe': {'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}},
                                        'systemImports': {'KERNEL32.dll': ['Present', 'Missing']}}))
        kernel = MagicMock()
        kernel.GetProcAddress.side_effect = lambda handle, name: None if name == b'Missing' else 1
        library = MagicMock()
        library._handle = 0x100000000
        def load(name, **kwargs):
            self.assertEqual(kwargs['winmode'], 0x800)
            return kernel if name == 'kernel32.dll' else library
        output = io.StringIO()
        with patch.object(ctypes, 'WinDLL', side_effect=load, create=True), redirect_stdout(output):
            acceptance.check_system_imports(runtime, manifest)
        self.assertIn('Missing system export: KERNEL32.dll!Missing', output.getvalue())
        self.assertIn('missing DLLs/exports: 1', output.getvalue())

    def test_acl_retry_grants_only_current_sid_rx_on_owned_pg_tree(self):
        runtime = self.root / 'payload'
        postgres = runtime / 'postgres'
        (postgres / 'bin').mkdir(parents=True)
        principal, sid = r'SYNTHETIC\runner', 'S-1-5-21-123-456-789-1001'
        environment = {'SystemRoot': r'C:\Windows', 'PATH': 'fixed-system-path'}
        companion = MagicMock()
        companion.probe_restricted_initdb.return_value = {'exitCode': 0}
        def command(arguments, **kwargs):
            self.assertEqual(kwargs['env'], environment)
            if arguments[0].endswith('whoami.exe'):
                output = ('"' + principal + '","' + sid + '"\n').encode()
            else:
                output = (str(postgres) + ' ' + principal + ':(F)\n').encode()
            return subprocess.CompletedProcess(arguments, 0, output, b'')
        output = io.StringIO()
        with (patch.object(acceptance.subprocess, 'run', side_effect=command) as run,
              patch.object(acceptance, 'run_postgres_probe', return_value=True) as retry,
              patch.dict(sys.modules, {'restricted_token_probe': companion}), redirect_stdout(output)):
            acceptance.restricted_acl_diagnostics(runtime, self.root, environment)
        grants = [call.args[0] for call in run.call_args_list if '/grant' in call.args[0]]
        self.assertEqual(grants, [[str(Path(r'C:\Windows') / 'System32/icacls.exe'), str(postgres),
                                   '/grant', '*' + sid + ':(OI)(CI)RX', '/T', '/Q']])
        retry.assert_called_once()
        self.assertEqual(retry.call_args.args[0], 'initdb-explicit-user-rx')
        self.assertIn('--auth-host=reject', retry.call_args.args[1])
        self.assertNotIn('PG_RESTRICT_EXEC', environment)
        companion.probe_restricted_initdb.assert_called_once_with(postgres / 'bin', self.root / 'restricted-child', environment)
        self.assertNotIn(principal, output.getvalue())
        self.assertNotIn(sid, output.getvalue())
        self.assertIn('does not override the original package probe failure', output.getvalue())

    def test_successful_diagnostic_does_not_hide_baseline_package_failure(self):
        with (patch.object(acceptance, 'run_postgres_probe', side_effect=[True, True, False]),
              patch.object(acceptance, 'check_system_imports'),
              patch.object(acceptance, 'restricted_acl_diagnostics') as diagnostic,
              redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'initdb-reject-auth'):
                acceptance.check_postgres_tools(self.install, self.root / 'probe', restricted_diagnostics=True)
        diagnostic.assert_called_once()

    def test_acl_query_error_does_not_prevent_restricted_child_probe(self):
        companion = MagicMock()
        companion.probe_restricted_initdb.return_value = {'exitCode': 0}
        output = io.StringIO()
        with (patch.object(acceptance, 'postgres_acl_retry', side_effect=OSError(5, 'synthetic private message')),
              patch.dict(sys.modules, {'restricted_token_probe': companion}), redirect_stdout(output)):
            acceptance.restricted_acl_diagnostics(self.install, self.root, {})
        companion.probe_restricted_initdb.assert_called_once()
        self.assertIn('Narrow PG ACL diagnostic unavailable: OSError', output.getvalue())
        self.assertNotIn('synthetic private message', output.getvalue())

    def test_fixture_root_gets_exact_user_system_protected_dacl_only(self):
        import ctypes
        sid = 'S-1-5-21-123-456-789-1001'
        security, kernel = MagicMock(), MagicMock()
        with (patch.object(acceptance, 'current_user_identity', return_value=['synthetic-user', sid]) as identity,
              patch.object(ctypes, 'WinDLL', side_effect=[security, kernel], create=True) as load,
              patch.dict(os.environ, {'PGPASSWORD': 'synthetic-private-password'})):
            acceptance.protect_fixture_root(self.root)
        sddl = security.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args.args[0]
        self.assertEqual(sddl, 'D:P(A;OICI;FA;;;' + sid + ')(A;OICI;FA;;;SY)')
        self.assertEqual(security.SetFileSecurityW.call_args.args[:2], (str(self.root), 0x80000004))
        self.assertNotIn('PGPASSWORD', identity.call_args.args[0])
        self.assertTrue(all(call.kwargs['winmode'] == 0x800 for call in load.call_args_list))
        kernel.LocalFree.assert_called_once()

    def test_fixture_context_only_protects_its_new_root_before_use(self):
        context = MagicMock()
        context.__enter__.return_value = str(self.root)
        with (patch.object(acceptance.tempfile, 'TemporaryDirectory', return_value=context) as temporary,
              patch.object(acceptance, 'protect_fixture_root') as protect):
            with acceptance.private_fixture_directory('kerix-postgres-only-') as root:
                self.assertEqual(root, self.root)
                protect.assert_called_once_with(self.root)
        temporary.assert_called_once_with(prefix='kerix-postgres-only-')
        context.__exit__.assert_called_once()
        with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'Unknown private fixture kind'):
            with acceptance.private_fixture_directory('arbitrary-existing-path'):
                self.fail('Unknown fixture kind accepted')

    def test_fixture_identity_refuses_malformed_or_multiple_sid_rows(self):
        for output in (b'"synthetic","S-1-5-21-12;untrusted"\n', b'"synthetic","S-0-5-123"\n',
                       b'"synthetic","S-1-5-21-1"\n"other","S-1-5-21-2"\n', b'"synthetic"\n'):
            with self.subTest(output=output), patch.object(acceptance.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')):
                with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'current-user SID is unavailable'):
                    acceptance.current_user_identity({})

    def test_app_timeout_keeps_bounded_startup_diagnostics_and_redacts_credentials(self):
        error = subprocess.TimeoutExpired(['fixture-owned-Kerix.exe'], 150,
            output=b'Electron startup: Cannot find module conf\n',
            stderr=b'x' * 20000 + b'\ngithubTokenEncryptionKey=fixture-private-bootstrap\nlicense_key=fixture-private-license\n'
                   b'eyJzdWIiOiJmaXh0dXJlIn0.cGF5bG9hZA.c2lnbmF0dXJl\n')
        output = io.StringIO()
        with patch.object(acceptance.subprocess, 'run', side_effect=error) as run, redirect_stdout(output):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'activation/preload smoke failed'):
                acceptance.check_app(self.install / 'Kerix.exe', self.root / 'app-profile')
        self.assertEqual(run.call_args.kwargs['timeout'], 150)
        self.assertIn('timeout after 150 seconds', output.getvalue())
        self.assertIn('Cannot find module conf', output.getvalue())
        self.assertNotIn('fixture-private-bootstrap', output.getvalue())
        self.assertNotIn('fixture-private-license', output.getvalue())
        self.assertNotIn('eyJzdWIiOiJmaXh0dXJlIn0', output.getvalue())
        self.assertIn('[sensitive app diagnostic omitted]', output.getvalue())
        self.assertLess(len(output.getvalue()), 2000)

    def test_app_timeout_cannot_pass_with_an_earlier_success_marker(self):
        error = subprocess.TimeoutExpired(['fixture-owned-Kerix.exe'], 150,
            output=b'KERIX_SMOKE_RESULT={"ok":true,"licenseLocked":true}\n')
        with patch.object(acceptance.subprocess, 'run', side_effect=error), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'activation/preload smoke failed'):
                acceptance.check_app(self.install / 'Kerix.exe', self.root / 'app-profile')

    def test_app_smoke_requires_successful_exit_and_a_valid_locked_marker(self):
        for code, marker, passed in [(0, '{"ok":true,"licenseLocked":true}', True),
                (1, '{"ok":true,"licenseLocked":true}', False),
                (0, '{"ok":true,"licenseLocked":false}', False), (0, 'invalid-json', False)]:
            result = subprocess.CompletedProcess([], code, ('KERIX_SMOKE_RESULT=' + marker + '\n').encode(), b'')
            with self.subTest(code=code, marker=marker), patch.object(acceptance.subprocess, 'run', return_value=result), redirect_stdout(io.StringIO()):
                if passed:
                    acceptance.check_app(self.install / 'Kerix.exe', self.root / 'app-profile')
                else:
                    with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'activation/preload smoke failed'):
                        acceptance.check_app(self.install / 'Kerix.exe', self.root / 'app-profile')


class RuntimeBootstrapTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kerix-bootstrap-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runtime = self.root / 'runtime'
        self.source = self.runtime / 'backend/app/desktop_runtime.py'
        self.source.parent.mkdir(parents=True)
        self.source.write_text('def read_parent_bootstrap(stream):\n    pass\n')
        self.key = '0123456789abcdef' * 4

    def test_both_runtime_starts_receive_one_private_key_and_flush_before_handoff(self):
        state = self.root / 'workspace'
        state.mkdir()
        (state / 'secrets.json').write_text(json.dumps({'database_password': 'fixture-db', 'signing_key': 'fixture-signing'}))
        owner = base64.urlsafe_b64encode(b'{"sub":"fixture-owner"}').decode().rstrip('=')
        handoff = json.dumps({'apiBaseUrl': 'http://127.0.0.1:45001/api/v1',
            'session': {'accessToken': 'header.' + owner + '.signature', 'refreshToken': 'fixture-refresh'}}).encode() + b'\n'
        children, wire = [], []

        def spawn(arguments, **kwargs):
            self.assertNotIn(self.key, repr(arguments))
            self.assertNotIn(self.key, repr(kwargs['env']))
            child = MagicMock()
            child.returncode = 0
            child.stdin.write.side_effect = lambda message: wire.append(message) or len(message)
            def read(_limit):
                child.stdin.flush.assert_called_once()
                self.assertEqual(json.loads(wire[-1]), {'version': 1, 'githubTokenEncryptionKey': self.key})
                return handoff
            child.stdout.readline.side_effect = read
            children.append(child)
            return child

        def open_api(request, **kwargs):
            if isinstance(request, str):
                response = MagicMock(); response.status = 200
                response.__enter__.return_value = response
                return response
            raise acceptance.HTTPError(request.full_url, 402, 'License required', {},
                io.BytesIO(b'{"detail":{"code":"LICENSE_REQUIRED"}}'))

        output = io.StringIO()
        with (patch.object(acceptance.secrets, 'token_urlsafe', return_value=self.key) as random_key,
              patch.object(acceptance, 'runtime_command', return_value=['fixture-runtime']),
              patch.object(acceptance.subprocess, 'Popen', side_effect=spawn),
              patch.object(acceptance.subprocess, 'CREATE_NO_WINDOW', 0, create=True),
              patch.object(acceptance.threading, 'Thread', side_effect=lambda *, target, daemon: SimpleNamespace(start=target)),
              patch.object(acceptance.OPENER, 'open', side_effect=open_api),
              patch.object(acceptance, 'cleanup_runtime', return_value=[]), redirect_stdout(output)):
            acceptance.check_runtime(self.runtime, state)
        random_key.assert_called_once_with(48)
        self.assertEqual(len(children), 2)
        self.assertEqual(wire[0], wire[1])
        self.assertTrue(wire[0].endswith(b'\n'))
        self.assertEqual(wire[0].count(b'\n'), 1)
        self.assertNotIn(self.key, output.getvalue())
        self.assertTrue(all(self.key.encode() not in entry.read_bytes() for entry in state.rglob('*') if entry.is_file()))
        self.assertIn('preserved state and shut down twice', output.getvalue())

    def test_upgrade_reuses_bootstrap_and_rejects_changed_owner_or_private_credentials(self):
        state = self.root / 'workspace'; state.mkdir()
        secret_file = state / 'secrets.json'
        secret_file.write_text(json.dumps({'database_password': 'fixture-db', 'signing_key': 'fixture-signing'}))
        expected = ('fixture-owner', acceptance.hashlib.sha256(secret_file.read_bytes()).hexdigest())
        owner = base64.urlsafe_b64encode(b'{"sub":"fixture-owner"}').decode().rstrip('=')
        handoff = json.dumps({'apiBaseUrl': 'http://127.0.0.1:45001/api/v1',
            'session': {'accessToken': 'header.' + owner + '.signature', 'refreshToken': 'fixture-refresh'}}).encode() + b'\n'
        child = MagicMock(); child.returncode = 0; child.stdout.readline.return_value = handoff
        bootstrap = (json.dumps({'version': 1, 'githubTokenEncryptionKey': self.key}) + '\n').encode()

        def open_api(request, **kwargs):
            if isinstance(request, str):
                response = MagicMock(); response.status = 200
                response.__enter__.return_value = response
                return response
            raise acceptance.HTTPError(request.full_url, 402, 'License required', {},
                io.BytesIO(b'{"detail":{"code":"LICENSE_REQUIRED"}}'))

        output = io.StringIO()
        with (patch.object(acceptance, 'runtime_parent_bootstrap') as generate_key,
              patch.object(acceptance, 'runtime_command', return_value=['fixture-runtime']),
              patch.object(acceptance.subprocess, 'Popen', return_value=child),
              patch.object(acceptance.subprocess, 'CREATE_NO_WINDOW', 0, create=True),
              patch.object(acceptance.threading, 'Thread', side_effect=lambda *, target, daemon: SimpleNamespace(start=target)),
              patch.object(acceptance.OPENER, 'open', side_effect=open_api),
              patch.object(acceptance, 'cleanup_runtime', return_value=[]), redirect_stdout(output)):
            self.assertEqual(acceptance.check_runtime(self.runtime, state, expected_identity=expected,
                parent_bootstrap=bootstrap), expected)
            for previous, message in [(('another-owner', expected[1]), 'Workspace owner changed'),
                                      ((expected[0], 'previous-secret-hash'), 'Private credentials changed')]:
                with self.subTest(message=message), self.assertRaisesRegex(acceptance.AcceptanceFailure, message):
                    acceptance.check_runtime(self.runtime, state, expected_identity=previous, parent_bootstrap=bootstrap)
        generate_key.assert_not_called()
        self.assertTrue(all(call.args == (bootstrap,) for call in child.stdin.write.call_args_list))
        self.assertNotIn(self.key, output.getvalue())

    def test_legacy_runtime_gets_no_bootstrap_shutdown_line_and_low_diversity_is_retried(self):
        self.source.write_text('def main():\n    pass\n')
        with patch.object(acceptance.secrets, 'token_urlsafe') as random_key:
            self.assertIsNone(acceptance.runtime_parent_bootstrap(self.runtime))
        random_key.assert_not_called()
        self.source.write_text('def read_parent_bootstrap(stream):\n    pass\n')
        with patch.object(acceptance.secrets, 'token_urlsafe', side_effect=['0' * 64, self.key]) as random_key:
            message = acceptance.runtime_parent_bootstrap(self.runtime)
        self.assertEqual(random_key.call_count, 2)
        self.assertEqual(json.loads(message)['githubTokenEncryptionKey'], self.key)

    def test_bootstrap_pipe_failure_reports_only_the_error_class_and_still_uninstalls(self):
        child = MagicMock(); child.returncode = 1
        child.stdin.flush.side_effect = OSError(22, 'private fixture key ' + self.key)
        output = io.StringIO()
        bootstrap = (json.dumps({'version': 1, 'githubTokenEncryptionKey': self.key}) + '\n').encode()
        with (patch.object(acceptance, 'runtime_parent_bootstrap', return_value=bootstrap),
              patch.object(acceptance, 'runtime_command', return_value=['fixture-runtime']),
              patch.object(acceptance.subprocess, 'Popen', return_value=child),
              patch.object(acceptance.subprocess, 'CREATE_NO_WINDOW', 0, create=True),
              patch.object(acceptance, 'cleanup_runtime', return_value=[]),
              patch.object(acceptance, 'check_app'), patch.object(acceptance, 'check_postgres_tools'),
              patch.object(acceptance, 'uninstall_app') as uninstall, redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): backend$'):
                acceptance.check_installed(self.runtime.parent, self.root)
        uninstall.assert_called_once()
        self.assertIn('backend acceptance failed: OSError', output.getvalue())
        self.assertNotIn(self.key, output.getvalue())

    def test_diagnostics_withhold_a_bootstrap_field_in_database_output(self):
        state = self.root / 'workspace'; state.mkdir()
        (state / 'secrets.json').write_text(json.dumps({'database_password': 'fixture-db', 'signing_key': 'fixture-signing'}))
        (state / 'logs').mkdir()
        (state / 'logs/database.log').write_text(json.dumps({'version': 1, 'githubTokenEncryptionKey': self.key}) + '\n')
        diagnostic = acceptance.runtime_diagnostics(state)
        self.assertNotIn(self.key, diagnostic)
        self.assertIn('[sensitive line omitted]', diagnostic)


class UpgradeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='kerix-upgrade-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.install = self.root / 'installed'
        self.previous = self.root / 'previous.exe'
        self.current = self.root / 'current.exe'
        self.identity = ('fixture-owner', 'fixture-private-secret-digest')
        self.bootstrap = b'{"version":1,"githubTokenEncryptionKey":"fixture-only"}\n'

    def test_upgrade_installs_over_same_directory_and_reopens_same_workspace(self):
        order = []
        def install(installer, destination):
            self.assertEqual(destination, self.install)
            order.append('install-old' if installer == self.previous else 'install-new')
        def runtime(_runtime, state, **kwargs):
            self.assertEqual(state, self.root / 'workspace')
            self.assertEqual(kwargs['parent_bootstrap'], self.bootstrap)
            order.append('backend-old' if 'expected_identity' not in kwargs else 'backend-new')
            if 'expected_identity' in kwargs:
                self.assertEqual(kwargs['expected_identity'], self.identity)
            return self.identity
        output = io.StringIO()
        with (patch.object(acceptance, 'install_app', side_effect=install),
              patch.object(acceptance, 'runtime_parent_bootstrap', return_value=self.bootstrap),
              patch.object(acceptance, 'check_runtime', side_effect=runtime),
              patch.object(acceptance, 'check_app', side_effect=lambda *args: order.append('app')),
              patch.object(acceptance, 'check_postgres_tools', side_effect=lambda *args: order.append('probes')),
              patch.object(acceptance, 'uninstall_app', side_effect=lambda *args: order.append('uninstall')),
              redirect_stdout(output)):
            acceptance.check_upgrade(self.current, self.previous, self.install, self.root)
        self.assertEqual(order, ['install-old', 'backend-old', 'install-new', 'app', 'probes', 'backend-new', 'uninstall'])
        self.assertIn('Manual NSIS upgrade preserved', output.getvalue())
        self.assertNotIn('fixture-only', output.getvalue())
        self.assertNotIn(self.identity[0], output.getvalue())

    def test_upgrade_identity_failure_still_uninstalls_without_claiming_success(self):
        output = io.StringIO()
        with (patch.object(acceptance, 'install_app'),
              patch.object(acceptance, 'runtime_parent_bootstrap', return_value=self.bootstrap),
              patch.object(acceptance, 'check_runtime', side_effect=[self.identity,
                  acceptance.AcceptanceFailure('Workspace owner changed on restart.')]),
              patch.object(acceptance, 'check_app'), patch.object(acceptance, 'check_postgres_tools'),
              patch.object(acceptance, 'uninstall_app') as uninstall, redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): upgraded-backend$'):
                acceptance.check_upgrade(self.current, self.previous, self.install, self.root)
        uninstall.assert_called_once_with(self.install)
        self.assertNotIn('Manual NSIS upgrade preserved', output.getvalue())

    def test_failed_previous_install_skips_dependent_checks_and_redacts_exception(self):
        output = io.StringIO()
        with (patch.object(acceptance, 'install_app', side_effect=OSError('fixture-private-installer-value')) as install,
              patch.object(acceptance, 'check_runtime') as runtime,
              patch.object(acceptance, 'check_app') as app,
              patch.object(acceptance, 'uninstall_app') as uninstall, redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): previous-install$'):
                acceptance.check_upgrade(self.current, self.previous, self.install, self.root)
        install.assert_called_once_with(self.previous, self.install)
        runtime.assert_not_called(); app.assert_not_called(); uninstall.assert_called_once()
        self.assertNotIn('fixture-private-installer-value', output.getvalue())

    def test_upgrade_app_failure_does_not_skip_runtime_or_cleanup(self):
        output = io.StringIO()
        with (patch.object(acceptance, 'install_app'),
              patch.object(acceptance, 'runtime_parent_bootstrap', return_value=self.bootstrap),
              patch.object(acceptance, 'check_runtime', return_value=self.identity) as runtime,
              patch.object(acceptance, 'check_app', side_effect=ValueError('fixture-private-app-value')),
              patch.object(acceptance, 'check_postgres_tools') as probes,
              patch.object(acceptance, 'uninstall_app') as uninstall, redirect_stdout(output)):
            with self.assertRaisesRegex(acceptance.AcceptanceFailure, r'phase\(s\): app$'):
                acceptance.check_upgrade(self.current, self.previous, self.install, self.root)
        self.assertEqual(runtime.call_count, 2)
        probes.assert_called_once(); uninstall.assert_called_once()
        self.assertNotIn('fixture-private-app-value', output.getvalue())

    def test_upgrade_requires_pinned_older_release_and_complete_acceptance(self):
        target, previous, digest = 'v1.0.3-preview.1', 'v1.0.2-preview.1', 'a' * 64
        acceptance.validate_upgrade_source(target, '', '', skip_app='0', pg_only='0')
        acceptance.validate_upgrade_source(target, previous, digest, skip_app='0', pg_only='0')
        for source, sha, skip, probe in [(previous, '', '0', '0'), ('', digest, '0', '0'),
                (previous, 'invalid', '0', '0'), (target, digest, '0', '0'),
                ('v1.0.4-preview.1', digest, '0', '0'), ('../v1.0.2-preview.1', digest, '0', '0'),
                (previous, digest, '1', '0'), (previous, digest, '0', '1')]:
            with self.subTest(source=source, skip=skip, probe=probe), self.assertRaises(acceptance.AcceptanceFailure):
                acceptance.validate_upgrade_source(target, source, sha, skip_app=skip, pg_only=probe)

    def test_download_requires_release_checksum_and_exact_candidate_pin(self):
        content = b'fixture-installer-not-executed'
        digest = acceptance.hashlib.sha256(content).hexdigest()
        name = 'kerix-desktop-1.0.2-setup.exe'
        def fetch(url, destination, limit):
            self.assertTrue(url.startswith('https://github.com/timmoyerr/kerix-downloads/releases/download/v1.0.2-preview.1/'))
            destination.write_bytes((digest + '  ' + name + '\n').encode() if url.endswith('SHA256SUMS') else content)
        for index, pin in enumerate((digest, 'b' * 64)):
            directory = self.root / str(index); directory.mkdir()
            with patch.object(acceptance, 'fetch', side_effect=fetch), redirect_stdout(io.StringIO()):
                if pin == digest:
                    self.assertEqual(acceptance.download_preview_installer('v1.0.2-preview.1', directory, pin), directory / name)
                else:
                    with self.assertRaisesRegex(acceptance.AcceptanceFailure, 'explicitly selected candidate'):
                        acceptance.download_preview_installer('v1.0.2-preview.1', directory, pin)


if __name__ == '__main__':
    unittest.main()
