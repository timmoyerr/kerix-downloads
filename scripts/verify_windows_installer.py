"""Public, credential-free acceptance for the published Kerix Windows preview."""
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

OPENER = build_opener(ProxyHandler({}))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


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
    require(result.returncode == 0 and isinstance(report, dict)
            and report.get('ok') is True and report.get('licenseLocked') is True,
            'Installed app activation/preload smoke failed.')
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
                    raise RuntimeError('Backend exposed the workspace without a license.')
                token = session['accessToken'].split('.')[1]
                current_owner = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))['sub']
                current_secrets = hashlib.sha256((state / 'secrets.json').read_bytes()).hexdigest()
                require(owner is None or owner == current_owner, 'Workspace owner changed on restart.')
                require(first_secrets is None or first_secrets == current_secrets, 'Private credentials changed on restart.')
                owner, first_secrets = current_owner, current_secrets
            finally:
                if child:
                    if child.poll() is None:
                        try:
                            child.stdin.write(b'stop\n')
                            child.stdin.flush()
                            child.stdin.close()
                            child.wait(timeout=55)
                        except (OSError, subprocess.TimeoutExpired):
                            subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=20)
                            child.wait(timeout=15)
                    for stream in (child.stdin, child.stdout, child.stderr):
                        if stream and not stream.closed:
                            stream.close()
        require(child.returncode == 0, 'Backend did not shut down cleanly.')
        require(not (state / 'postgres/postmaster.pid').exists(), 'Backend left its PostgreSQL process running.')
    print('Bundled Python/PostgreSQL initialized, migrated, stayed locked, preserved state and shut down twice.')


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


def main():
    tag = os.environ.get('KERIX_RELEASE_TAG', '')
    match = re.fullmatch(r'v(\d+\.\d+\.\d+)-preview\.[1-9]\d*', tag)
    require(os.name == 'nt' and match is not None, 'Use a valid published preview tag on Windows.')
    version = match.group(1)
    name = 'kerix-desktop-' + version + '-setup.exe'
    base = 'https://github.com/timmoyerr/kerix-downloads/releases/download/' + tag + '/'
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
        install = root / 'installed'
        completed = subprocess.run([str(installer), '/S', '/D=' + str(install)], timeout=180)
        require(completed.returncode == 0, 'Silent NSIS installation failed.')
        executable = install / 'Kerix.exe'
        require(executable.is_file(), 'NSIS did not install Kerix.')
        try:
            check_app(executable, root / 'app-profile')
            state = root / 'workspace'; state.mkdir()
            check_runtime(install / 'resources/personal-runtime', state)
        finally:
            uninstall = install / 'Uninstall Kerix.exe'
            require(uninstall.is_file(), 'NSIS uninstaller is missing.')
            subprocess.run([str(uninstall), '/S'], timeout=120, check=True)
            # NSIS may spawn a temporary uninstaller process before returning.
            import time
            deadline = time.monotonic() + 60
            while executable.exists() and time.monotonic() < deadline:
                time.sleep(0.5)
            require(not executable.exists(), 'NSIS uninstall left the installed app behind.')
        print('Downloaded checksum, NSIS install and uninstall passed on Windows Server 2022.')


if __name__ == '__main__':
    main()
