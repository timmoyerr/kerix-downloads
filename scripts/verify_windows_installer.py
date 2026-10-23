"""Public, credential-free acceptance for the published Kerix Windows preview."""
import base64
import csv
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import stat
import unicodedata
from pathlib import PurePosixPath
from zipfile import ZipFile
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from urllib.parse import quote, quote_plus

OPENER = build_opener(ProxyHandler({}))


class AcceptanceFailure(RuntimeError):
    """Only fixed, author-written acceptance diagnostics belong in this error."""


def runtime_diagnostics(data):
    """Read only this generated fixture's logs; never expose its credentials."""
    secrets = []
    try:
        path = data / 'secrets.json'
        if path.is_symlink() or path.stat().st_size > 4096:
            raise ValueError
        values = json.loads(path.read_bytes())
        if set(values) != {'database_password', 'signing_key'} or any(not isinstance(value, str) or not value for value in values.values()):
            raise ValueError
        for value in values.values():
            secrets.extend((value, quote(value, safe=''), quote_plus(value), json.dumps(value)[1:-1]))
    except (OSError, ValueError, TypeError):
        pass
    safe_runtime = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_.]*(?:Error|Failure|Exception) at [A-Za-z0-9_.,: <>-]+|Missing bundled module: [A-Za-z0-9_.]+|Kerix could not start its private runtime\. Existing user data is preserved\.)$')
    sensitive = re.compile(r'://|password|signing_key|secret_key|database_url|authorization|(?:access|refresh)[_-]?token|connection[_ -]?(?:key|url)|\bdsn\b', re.I)
    jwt = re.compile(r'[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}')
    result = []
    files = ('acceptance.log', 'logs/database-initialize.log', 'logs/database-start.log', 'logs/database.log', 'logs/database-stop.log')
    for name in files:
        path = data / name
        try:
            if path.is_symlink():
                result.append(name + ': linked log withheld')
                continue
            size = path.stat().st_size
            result.append(name + ': ' + str(size) + ' bytes')
            with path.open('rb') as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell() - 16384))
                lines = stream.read(16384).decode('utf-8', errors='replace').splitlines()[-20:]
        except OSError as error:
            result.append(name + ': unavailable (' + type(error).__name__ + ', errno=' + str(error.errno) + ')')
            continue
        cleaned = []
        for line in lines:
            for value in sorted(set(secrets), key=len, reverse=True):
                line = line.replace(value, '[REDACTED]')
            line = jwt.sub('[REDACTED TOKEN]', line)
            if sensitive.search(line):
                # Keep a useful fixed diagnostic phrase, never the original
                # credential-bearing line or a database connection URL.
                phrases = ('permission denied', 'access is denied', 'invalid locale', 'dll load failed', 'could not execute', 'could not create directory')
                reason = next((value for value in phrases if value in line.lower()), None)
                line = '[sensitive line omitted' + ('; ' + reason if reason else '') + ']'
            elif not secrets and not safe_runtime.fullmatch(line.strip()):
                continue  # Redaction unavailable: raw database diagnostics withheld.
            cleaned.append(line[:600])
        if cleaned:
            result.append(name + ':\n' + '\n'.join(cleaned)[-2500:])
    if not secrets:
        result.append('Fixture credential redaction unavailable; raw database diagnostics withheld.')
    return '\n'.join(result)[:8000] or 'No runtime diagnostics were available.'


def require(condition, message):
    if not condition:
        raise AcceptanceFailure(message)


def fetch(url, destination, limit):
    with OPENER.open(url, timeout=90) as response, destination.open('xb') as output:
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            require(size <= limit, 'A release asset exceeds its size limit.')
            output.write(chunk)


def check_app(executable, profile):
    result = subprocess.run([str(executable), '--kerix-smoke-test', '--user-data-dir=' + str(profile)],
                            env=dict(os.environ, KERIX_NATIVE_SMOKE='1'), capture_output=True, timeout=150)
    # Handoff credentials are never included in this application smoke output.
    lines = (result.stdout + result.stderr).decode('utf-8', errors='replace').splitlines()
    marker = next((line.removeprefix('KERIX_SMOKE_RESULT=') for line in lines
                   if line.startswith('KERIX_SMOKE_RESULT=')), 'null')
    report = json.loads(marker)
    ok = result.returncode == 0 and isinstance(report, dict) and report.get('ok') is True and report.get('licenseLocked') is True
    if not ok:
        print('App exit status:', result.returncode, flush=True)
        print('Smoke marker present:', marker != 'null', flush=True)
        for line in lines[-30:]:
            if re.search(r'password|authorization|signing_key|secret_key|(?:access|refresh)[_-]?token', line, re.I):
                print('[sensitive app diagnostic omitted]', flush=True)
            else:
                print(line[:600], flush=True)
    require(ok, 'Installed app activation/preload smoke failed.')
    print('Installed Electron activation gate and preload passed.')


def check_runtime(runtime, state):
    """Launch twice from an empty private workspace and verify backend locking."""
    owner = None
    first_secrets = None
    for _ in range(2):
        environment = {name: value for name, value in os.environ.items() if name in
                       {'HOME', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP',
                        'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'}}
        command = runtime_command(runtime)
        child = None
        failure = None
        with (state / 'acceptance.log').open('ab') as log:
            try:
                child = subprocess.Popen(command + ['--state-dir', str(state), '--postgres-root', str(runtime / 'postgres')],
                                         cwd=state, env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=log, creationflags=subprocess.CREATE_NO_WINDOW)
                handoff = queue.Queue()
                threading.Thread(target=lambda: handoff.put(child.stdout.readline(65537)), daemon=True).start()
                line = handoff.get(timeout=180)
                require(bool(line) and len(line) <= 65536, 'Bundled backend exited or supplied an invalid handoff.')
                payload = json.loads(line)
                api = payload.get('apiBaseUrl', '')
                require(re.fullmatch(r'http://127\.0\.0\.1:\d{1,5}/api/v1', api), 'Unexpected backend loopback address.')
                session = payload.get('session', {})
                require(isinstance(session.get('accessToken'), str) and isinstance(session.get('refreshToken'), str),
                        'Missing private runtime session.')
                with OPENER.open(api.removesuffix('/api/v1') + '/health/ready', timeout=10) as response:
                    require(response.status == 200, 'Bundled backend/database are not ready.')
                request = Request(api + '/auth/me', headers={'Authorization': 'Bearer ' + session['accessToken']})
                try:
                    OPENER.open(request, timeout=10).close()
                except HTTPError as error:
                    try:
                        require(error.code == 402 and json.loads(error.read()).get('detail', {}).get('code') == 'LICENSE_REQUIRED',
                                'Backend did not enforce the license requirement.')
                    finally:
                        error.close()
                else:
                    raise AcceptanceFailure('Backend exposed the workspace without a license.')
                token = session['accessToken'].split('.')[1]
                current_owner = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))['sub']
                current_secrets = hashlib.sha256((state / 'secrets.json').read_bytes()).hexdigest()
                require(owner is None or owner == current_owner, 'Workspace owner changed on restart.')
                require(first_secrets is None or first_secrets == current_secrets, 'Private credentials changed on restart.')
                owner, first_secrets = current_owner, current_secrets
            except BaseException as error:
                failure = error
                raise
            finally:
                issues = cleanup_runtime(child)
                print('Runtime exit status:', exit_status(child.returncode if child else None), flush=True)
                if issues:
                    print('Runtime cleanup diagnostics (classes/numeric codes only): ' + ', '.join(issues), flush=True)
                if failure is not None:
                    failure.add_note(runtime_diagnostics(state))
                elif issues:
                    raise AcceptanceFailure('Runtime cleanup failed.')
        require(child.returncode == 0, 'Backend did not shut down cleanly.')
        require(not (state / 'postgres/postmaster.pid').exists(), 'Backend left its PostgreSQL process running.')
    print('Bundled Python/PostgreSQL initialized, migrated, stayed locked, preserved state and shut down twice.')


def exit_status(value):
    return 'unavailable' if value is None else str(value) + ' (0x' + format(value & 0xffffffff, '08X') + ')'


def cleanup_runtime(child):
    """Never replace the first failure with Windows pipe flush/close errors."""
    if child is None:
        return []
    issues = []
    def attempt(name, operation):
        try:
            operation()
            return True
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            issues.append(name + ':' + type(error).__name__ + ':errno=' + str(getattr(error, 'errno', None)) + ':winerror=' + str(getattr(error, 'winerror', None)))
            return False
    try:
        try:
            running = child.poll() is None
        except OSError as error:
            issues.append('poll:' + type(error).__name__ + ':errno=' + str(error.errno) + ':winerror=' + str(getattr(error, 'winerror', None)))
            running = True
        if running and child.stdin is not None:
            attempt('stop-write', lambda: child.stdin.write(b'stop\n'))
            attempt('stop-flush', child.stdin.flush)
        if child.stdin is not None:
            attempt('stdin-close', child.stdin.close)
        if not attempt('wait', lambda: child.wait(timeout=55)):
            taskkill = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/taskkill.exe')
            attempt('owned-tree-stop', lambda: subprocess.run([taskkill, '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=20))
            if not attempt('tree-wait', lambda: child.wait(timeout=15)):
                attempt('kill', child.kill)
                attempt('kill-wait', lambda: child.wait(timeout=10))
    finally:
        for name in ('stdin', 'stdout', 'stderr'):
            stream = getattr(child, name, None)
            if stream is not None and not stream.closed:
                attempt(name + '-close', stream.close)
    return issues


def probe_output(value):
    """These probes never receive credentials, environment secrets or sessions."""
    output = []
    for line in value.decode('utf-8', errors='replace').splitlines()[-30:]:
        if re.search(r'://|password|authorization|signing_key|secret_key|(?:access|refresh)[_-]?token|[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}', line, re.I):
            output.append('[sensitive probe diagnostic omitted]')
        else:
            output.append(line[:600])
    return '\n'.join(output)[-8000:]


def run_postgres_probe(name, command, directory, environment):
    """Return probe success while always reporting its exact safe exit status."""
    child = None
    try:
        child = subprocess.Popen(command, cwd=directory, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
        timed_out = False
        try:
            stdout, stderr = child.communicate(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            taskkill = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32/taskkill.exe')
            subprocess.run([taskkill, '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=20)
            stdout, stderr = child.communicate(timeout=15)
        print(name + ' exit status: ' + exit_status(child.returncode), flush=True)
        if timed_out:
            print(name + ' exceeded the bounded probe timeout.', flush=True)
        for label, content in (('stdout', stdout), ('stderr', stderr)):
            print(name + ' ' + label + ': ' + str(len(content)) + ' bytes', flush=True)
            if content:
                print(probe_output(content), flush=True)
        return not timed_out and child.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as error:
        print(name + ' process failure: ' + type(error).__name__ + ' errno=' + str(getattr(error, 'errno', None)) + ' winerror=' + str(getattr(error, 'winerror', None)), flush=True)
        return False
    finally:
        if child is not None:
            if child.poll() is None:
                cleanup_runtime(child)
            for stream in (child.stdout, child.stderr):
                if stream and not stream.closed:
                    stream.close()


def postgres_acl_retry(runtime, directory, environment):
    """Only an extracted, owned PG tree receives the diagnostic user RX ACE."""
    system = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
    identity = subprocess.run([str(system / 'whoami.exe'), '/user', '/fo', 'csv', '/nh'],
                              env=environment, capture_output=True, timeout=20, check=True)
    rows = list(csv.reader(identity.stdout.decode('utf-8', errors='replace').splitlines()))
    require(len(rows) == 1 and len(rows[0]) == 2 and re.fullmatch(r'S-1-\d+(?:-\d+){1,15}', rows[0][1]),
            'The diagnostic current-user SID is unavailable.')
    principal, sid = rows[0]
    postgres = runtime / 'postgres'
    require(postgres.is_dir() and not postgres.is_symlink(), 'The owned diagnostic PostgreSQL tree is unavailable.')
    icacls = str(system / 'icacls.exe')
    for relative in ('', 'bin', 'bin/initdb.exe', 'bin/libpq.dll'):
        result = subprocess.run([icacls, str(postgres / relative)], env=environment,
                                capture_output=True, timeout=20)
        print('PG ACL ' + (relative or '.') + ' query exit status: ' + exit_status(result.returncode), flush=True)
        raw = result.stdout + result.stderr
        for value, replacement in ((str(postgres), '<POSTGRES>'), (principal, '<CURRENT_USER>'), (sid, '<CURRENT_USER_SID>')):
            raw = raw.replace(value.encode('utf-8'), replacement.encode('ascii'))
        if raw:
            print(probe_output(raw), flush=True)
    # Use an explicit SID, never a name lookup, and never change the workspace,
    # data directories, parent folders or any Windows/system directory ACLs.
    result = subprocess.run([icacls, str(postgres), '/grant', '*' + sid + ':(OI)(CI)RX', '/T', '/Q'],
                            env=environment, capture_output=True, timeout=60)
    print('PG-tree-only current-user RX grant exit status: ' + exit_status(result.returncode), flush=True)
    if result.returncode:
        print('PG-tree ACL retry unavailable: the narrow grant failed.', flush=True)
        return
    binary = postgres / 'bin'
    retry = ['--auth-host=reject', '--auth-local=reject', '--username=kerix_owner', '--encoding=UTF8', '--locale=C',
             '-D', str(directory / 'postgres-explicit-user-rx')]
    run_postgres_probe('initdb-explicit-user-rx', [str(binary / 'initdb.exe'), *retry], directory, environment)
    print('The ACL retry is diagnostic only; it does not override the original package probe failure.', flush=True)


def restricted_acl_diagnostics(runtime, directory, environment):
    try:
        postgres_acl_retry(runtime, directory, environment)
    except Exception as error:
        print('Narrow PG ACL diagnostic unavailable: ' + type(error).__name__, flush=True)
    # The companion probe creates a real source-equivalent restricted token;
    # it does not set PG_RESTRICT_EXEC or weaken PostgreSQL's self-restriction.
    from restricted_token_probe import probe_restricted_initdb
    report = probe_restricted_initdb(runtime / 'postgres/bin', directory / 'restricted-child', environment)
    require(isinstance(report, dict), 'The restricted-child diagnostic supplied an invalid report.')
    print('Restricted initdb-version child diagnostic:', probe_output(json.dumps(report, sort_keys=True).encode()), flush=True)


def check_postgres_tools(runtime, directory, *, restricted_diagnostics=False):
    """Loader/initdb contrast outside the runtime's private Windows job."""
    directory.mkdir()
    binary = runtime / 'postgres/bin'
    environment = {name: value for name, value in os.environ.items() if name in
                   {'HOME', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'}}
    environment.update(PATH=str(binary) + os.pathsep + str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'), LANG='C', LC_ALL='C')
    probes = [('postgres-version', [str(binary / 'postgres.exe'), '--version']),
              ('initdb-version', [str(binary / 'initdb.exe'), '--version']),
              ('initdb-reject-auth', [str(binary / 'initdb.exe'), '--auth-host=reject', '--auth-local=reject',
                                      '--username=kerix_owner', '--encoding=UTF8', '--locale=C', '-D', str(directory / 'postgres')])]
    failures = []
    for name, command in probes:
        if not run_postgres_probe(name, command, directory, environment):
            failures.append(name)
    if failures:
        check_system_imports(runtime)
        if restricted_diagnostics:
            try:
                restricted_acl_diagnostics(runtime, directory, environment)
            except Exception as error:
                print('Restricted-child diagnostic unavailable: ' + type(error).__name__, flush=True)
    require(not failures, 'Installed PostgreSQL tool probes failed: ' + ', '.join(failures))


def check_system_imports(runtime, manifest_path=None):
    """Resolve only declared OS exports from System32, never application DLLs."""
    manifest = json.loads(Path(manifest_path or Path(__file__).with_name('pg-windows-system-imports.json')).read_text())
    for name, record in manifest['binaries'].items():
        binary = runtime / 'postgres/bin' / name
        if not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != record['sha256']:
            print('System import preflight SKIPPED: supplied binary inventory differs.', flush=True)
            return
    import ctypes
    kernel = ctypes.WinDLL('kernel32.dll', use_last_error=True, winmode=0x800)
    kernel.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    kernel.GetProcAddress.restype = ctypes.c_void_p
    missing = 0
    for name, symbols in sorted(manifest['systemImports'].items()):
        require(re.fullmatch(r'[A-Za-z0-9_.-]+\.dll', name), 'Invalid diagnostic system DLL name.')
        try:
            library = ctypes.WinDLL(name, use_last_error=True, winmode=0x800)
        except OSError as error:
            missing += 1
            print('Missing system DLL: ' + name + ' winerror=' + str(getattr(error, 'winerror', None)), flush=True)
            continue
        for symbol in symbols:
            require(re.fullmatch(r'[A-Za-z0-9_?@$]+', symbol), 'Invalid diagnostic system export name.')
            if not kernel.GetProcAddress(library._handle, symbol.encode('ascii')):
                missing += 1
                print('Missing system export: ' + name + '!' + symbol, flush=True)
    print('System import preflight missing DLLs/exports: ' + str(missing), flush=True)


def extract_probe(archive, destination):
    """Only regular files below postgres/ may leave this fixed hash-pinned ZIP."""
    reserved = {'con', 'prn', 'aux', 'nul', *('com' + str(i) for i in range(1, 10)), *('lpt' + str(i) for i in range(1, 10))}
    with ZipFile(archive) as source:
        members = source.infolist()
        require(len(members) <= 5000 and sum(item.file_size for item in members) <= 512 * 1024 * 1024,
                'PostgreSQL probe ZIP exceeds its extraction limit.')
        seen = set()
        for member in members:
            name = member.filename
            parts = PurePosixPath(name).parts
            key = unicodedata.normalize('NFC', name.rstrip('/')).casefold()
            kind = stat.S_IFMT(member.external_attr >> 16)
            require(parts and parts[0] == 'postgres' and not PurePosixPath(name).is_absolute()
                    and '\\' not in name and len(name) <= 1024 and key not in seen
                    and kind in {0, stat.S_IFREG, stat.S_IFDIR}
                    and all(part not in {'.', '..'} and part[-1:] not in {' ', '.'}
                            and part.split('.')[0].casefold() not in reserved
                            and not any(ord(character) < 32 or character in '<>:"|?*' for character in part) for part in parts),
                    'Unsafe PostgreSQL probe ZIP member.')
            seen.add(key)
        destination.mkdir()
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.filename).parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.open(member) as input_, target.open('xb') as output:
                    while chunk := input_.read(1024 * 1024):
                        output.write(chunk)


def probe_only(base, expected_sha):
    require(re.fullmatch(r'[a-f0-9]{64}', expected_sha), 'An exact PostgreSQL probe SHA256 is required.')
    with tempfile.TemporaryDirectory(prefix='kerix-postgres-only-') as directory:
        root = Path(directory)
        archive = root / 'probe.zip'
        fetch(base + 'kerix-postgresql-16.13-win32-x64-probe.zip', archive, 64 * 1024 * 1024)
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == expected_sha, 'PostgreSQL probe checksum differs.')
        print('Verified PostgreSQL probe SHA256:', expected_sha, flush=True)
        print('PG-ONLY diagnostic: app, installer and Python/backend acceptance are NOT performed.', flush=True)
        extract_probe(archive, root / 'payload')
        check_postgres_tools(root / 'payload', root / 'probe-state', restricted_diagnostics=True)


def runtime_command(runtime):
    manifest = json.loads((runtime / 'runtime-manifest.json').read_text())
    require(manifest.get('platform') == 'win32' and manifest.get('architecture') in ('AMD64', 'x86_64', 'x64'),
            'The installer contains a foreign runtime.')
    if manifest.get('runtimeKind') == 'python-embedded':
        require(manifest.get('pythonVersion') == '3.12.15'
                and manifest.get('pythonExecutable') == 'python/python.exe'
                and manifest.get('entryPoint') == 'windows-runtime-entry.py',
                'The embedded Windows interpreter/entrypoint is not the pinned distribution.')
        executable, entry = runtime / 'python/python.exe', runtime / 'windows-runtime-entry.py'
        require(executable.is_file() and entry.is_file(), 'The embedded backend is incomplete.')
        return [str(executable), '-I', '-S', '-u', str(entry)]
    require(manifest.get('runtimeKind') is None, 'Unknown backend runtime format.')
    executable = runtime / 'kerix-runtime/kerix-runtime.exe'
    require(executable.is_file(), 'The installer is missing its backend executable.')
    return [str(executable)]


def uninstall_app(install):
    executable = install / 'Kerix.exe'
    uninstall = install / 'Uninstall Kerix.exe'
    require(uninstall.is_file(), 'NSIS uninstaller is missing.')
    subprocess.run([str(uninstall), '/S'], timeout=120, check=True)
    # NSIS may spawn a temporary uninstaller process before returning.
    import time
    deadline = time.monotonic() + 60
    while executable.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    require(not executable.exists(), 'NSIS uninstall left the installed app behind.')


def check_installed(install, root, *, skip_app=False):
    """Independent phases keep an app IPC failure from hiding runtime results."""
    failures = []
    state = root / 'workspace'
    state.mkdir()

    def attempt(phase, operation):
        try:
            operation()
        except Exception as error:
            failures.append(phase)
            # Arbitrary exception values may contain fixture credentials. Only
            # our fixed assertions and explicitly redacted logs are printable.
            diagnostic = str(error) if isinstance(error, AcceptanceFailure) else type(error).__name__
            print(phase + ' acceptance failed: ' + diagnostic, flush=True)
            if phase == 'backend':
                print(runtime_diagnostics(state), flush=True)

    try:
        if skip_app:
            print('App activation/preload smoke SKIPPED: this run verifies the backend only.', flush=True)
        else:
            attempt('app', lambda: check_app(install / 'Kerix.exe', root / 'app-profile'))
        attempt('postgres-probes', lambda: check_postgres_tools(install / 'resources/personal-runtime', root / 'postgres-probes'))
        attempt('backend', lambda: check_runtime(install / 'resources/personal-runtime', state))
    finally:
        attempt('uninstall', lambda: uninstall_app(install))
    require(not failures, 'Installer acceptance failed in phase(s): ' + ', '.join(failures))


def main():
    tag = os.environ.get('KERIX_RELEASE_TAG', '')
    match = re.fullmatch(r'v(\d+\.\d+\.\d+)-preview\.[1-9]\d*', tag)
    require(os.name == 'nt' and match is not None, 'Use a valid published preview tag on Windows.')
    skip_app = os.environ.get('KERIX_SKIP_APP_SMOKE', '0')
    require(skip_app in {'0', '1'}, 'Use KERIX_SKIP_APP_SMOKE=0 or 1 explicitly.')
    expected_sha = os.environ.get('KERIX_EXPECTED_INSTALLER_SHA256', '')
    require(not expected_sha or re.fullmatch(r'[a-f0-9]{64}', expected_sha), 'The optional expected installer checksum is invalid.')
    version = match.group(1)
    name = 'kerix-desktop-' + version + '-setup.exe'
    base = 'https://github.com/timmoyerr/kerix-downloads/releases/download/' + tag + '/'
    pg_only = os.environ.get('KERIX_PG_PROBE_ONLY', '0')
    require(pg_only in {'0', '1'}, 'Use KERIX_PG_PROBE_ONLY=0 or 1 explicitly.')
    if pg_only == '1':
        probe_only(base, os.environ.get('KERIX_PG_PROBE_SHA256', ''))
        return
    with tempfile.TemporaryDirectory(prefix='kerix-installer-acceptance-') as directory:
        root = Path(directory)
        checksum_path, installer = root / 'SHA256SUMS', root / name
        fetch(base + 'SHA256SUMS', checksum_path, 1024 * 1024)
        checksums = {}
        for line in checksum_path.read_text().splitlines():
            match_line = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_.-]+)', line)
            require(match_line is not None, 'Malformed release checksum file.')
            require(match_line.group(2) not in checksums, 'Duplicate checksum entry.')
            checksums[match_line.group(2)] = match_line.group(1)
        require(name in checksums, 'The installer checksum is missing.')
        fetch(base + name, installer, 1024 ** 3)
        with installer.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        require(digest == checksums[name], 'The downloaded installer checksum differs.')
        require(not expected_sha or digest == expected_sha, 'The installer differs from the explicitly selected candidate.')
        print('Verified installer SHA256:', digest, flush=True)
        install = root / 'installed'
        completed = subprocess.run([str(installer), '/S', '/D=' + str(install)], timeout=180)
        require(completed.returncode == 0, 'Silent NSIS installation failed.')
        executable = install / 'Kerix.exe'
        require(executable.is_file(), 'NSIS did not install Kerix.')
        check_installed(install, root, skip_app=skip_app == '1')
        print('Downloaded checksum, NSIS install and uninstall passed on Windows Server 2022.')


if __name__ == '__main__':
    main()
