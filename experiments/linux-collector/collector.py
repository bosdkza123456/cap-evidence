"""Research-only Linux collector. No CAP evidence, authentication or authorization.
Never runs an arbitrary package. CLI executes only the bundled controlled workload.
"""
import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import uuid
import stat

MAX_BYTES = 1 << 20

def digest(data):
    return hashlib.sha256(data).hexdigest()

class Blocked(Exception):
    """Fixed reason only, never include raw stderr, paths or commands."""


def probe():
    result = {}
    commands = {
        'tracing': ['strace', '-qq', '-o', os.devnull, '/bin/true'],
        'sandbox': [*sandbox_args('/tmp'), '/bin/true'],
        'compiler': ['cc', '--version'],
    }
    for key, command in commands.items():
        if not shutil.which(command[0]):
            result[key] = 'unavailable'
            continue
        try:
            p = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
            result[key] = 'available' if p.returncode == 0 else 'blocked'
        except (OSError, subprocess.TimeoutExpired):
            result[key] = 'blocked'
    return result

# Supported strace presentation is deliberately narrow. Truncation/unfinished
# calls and unresolved FD identity remain visible as unmapped events.
LINE = re.compile(r'^(?:\d+\s+)?(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+)(.*)$')
FD = re.compile(r'^\d+<([^<>]+)>\s*,')
NET = re.compile(r'sin6?_port=htons\((\d+)\)')
IP4 = re.compile(r'inet_addr\("([0-9.]+)"\)')
IP6 = re.compile(r'inet_pton\(AF_INET6, "([0-9a-fA-F:]+)"')


def parse_trace(raw, run_id):
    if len(raw) > MAX_BYTES:
        raise Blocked('trace_resource_limit')
    try:
        text = raw.decode('utf-8', 'strict')
    except UnicodeError:
        raise Blocked('trace_invalid_encoding') from None
    events, failures = [], 0
    for index, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        if len(events) >= 1024:
            raise Blocked('trace_record_limit')
        m = LINE.fullmatch(line)
        # Exit markers are collector metadata, never evidence.
        if re.fullmatch(r'(?:\d+\s+)?\d+\.\d+\s+\+\+\+ exited with \d+ \+\+\+', line):
            continue
        e = {'id': f'{run_id}:{index}', 'phase': 'controlled', 'operation': 'unsupported',
             'result': 'unknown', 'observed_at': '1970-01-01T00:00:00Z'}
        if not m:
            failures += 1
            events.append(e)
            continue
        timestamp, call, args, ret, tail = m.groups()
        try:
            e['observed_at'] = dt.datetime.fromtimestamp(float(timestamp), dt.timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            failures += 1
            events.append(e)
            continue
        e['result'] = 'succeeded' if int(ret) >= 0 else 'failed'
        if 'EINPROGRESS' in tail:
            e['result'] = 'attempted'
        # Truncated strings/unfinished traces are not safe target identities.
        if '...' in args or '\\' in args or '<unfinished' in line:
            failures += 1
        elif call in ('connect', 'bind'):
            port, host = NET.search(args), (IP4.search(args) or IP6.search(args))
            if port and host and 0 <= int(port[1]) <= 65535:
                try:
                    ipaddress.ip_address(host[1])
                    e.update(operation=call, host=host[1], port=int(port[1]))
                except ValueError:
                    failures += 1
            else:
                failures += 1
        elif call in ('read', 'write'):
            fd = FD.search(args)
            if fd and fd[1].startswith('/'):
                e.update(operation=call, path=fd[1])
            else:
                failures += 1
        elif call == 'unlink':
            path = re.fullmatch(r'"([^"\\]+)"', args)
            if path:
                e.update(operation='delete', path=path[1])
            else:
                failures += 1
        elif call == 'execve':
            exe = re.match(r'^"([^"\\]+)",', args)
            if exe:
                e.update(operation='exec', executable=exe[1])
            else:
                failures += 1
        # stat/openat/etc remain unsupported, never inferred as content read.
        events.append(e)
        if len(events) > 1024:
            raise Blocked('trace_record_limit')
    return events, failures


def accept(payload, binding, database, now, max_age=300):
    """Local one-use ledger; caller-owned binding, not remote authentication."""
    if len(payload) > MAX_BYTES:
        raise Blocked('payload_resource_limit')
    if not isinstance(binding, dict) or not isinstance(binding.get('payload_digest'), str):
        raise Blocked('invalid_local_envelope')
    if digest(payload) != binding['payload_digest']:
        raise Blocked('payload_binding_mismatch')
    try:
        doc = json.loads(payload)
        for key in ('run_id', 'artifact_digest', 'analyzer'):
            if doc[key] != binding[key]:
                raise Blocked('run_binding_mismatch')
        ended = dt.datetime.fromisoformat(binding['ended_at'])
        started = dt.datetime.fromisoformat(binding['started_at'])
        if ended.tzinfo is None or started.tzinfo is None or now.tzinfo is None or started > ended:
            raise Blocked('invalid_run_time')
        age = (now - ended).total_seconds()
        if not 0 <= age <= max_age:
            raise Blocked('run_not_fresh')
        for event in doc['events']:
            stamp = dt.datetime.fromisoformat(event['observed_at'])
            started = dt.datetime.fromisoformat(binding['started_at'])
            if not started <= stamp <= ended:
                raise Blocked('event_outside_run')
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Blocked('invalid_local_envelope') from None
    # Persistent transaction serializes replay acceptance. Only successful
    # binding checks consume a run. Payload remains inspection-only.
    try:
        private_ledger(database)
        with sqlite3.connect(database, timeout=5) as db:
            db.execute('CREATE TABLE IF NOT EXISTS accepted (run TEXT PRIMARY KEY, payload TEXT NOT NULL)')
            db.execute('INSERT INTO accepted VALUES (?,?)', (binding['run_id'], binding['payload_digest']))
    except sqlite3.IntegrityError:
        raise Blocked('replayed_run') from None
    except sqlite3.Error:
        raise Blocked('replay_store_unavailable') from None
    return {'authorization_ready': False, 'reason': 'inspection_only', 'events': len(doc['events'])}


def private_ledger(database):
    path = Path(database)
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise Blocked('replay_directory_not_private')
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise Blocked('replay_store_not_private')


def sandbox_args(work):
    # Empty root; only toolchain runtime directories, never host /home or /etc.
    args = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--tmpfs', '/']
    for name in ('/usr', '/bin', '/lib', '/lib64'):
        if Path(name).exists():
            args += ['--ro-bind', name, name]
    args += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
             '--dir', '/work', '--bind', str(work), '/work', '--chdir', '/work',
             '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin']
    return args


def attribution(raw, run_id):
    """Conservative source-local PID ownership; ambiguous records stay unknown."""
    known, records = set(), []
    pattern = re.compile(r'^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+)(.*)$')
    for index, line in enumerate(raw.decode('utf-8', 'strict').splitlines()):
        exit_match = re.match(r'^(\d+)\s+\d+\.\d+\s+\+\+\+ (?:exited|killed)', line)
        if exit_match:
            known.discard(exit_match[1])
        match = pattern.fullmatch(line)
        owner, pid = 'unknown', None
        if match:
            pid, _, call, args, ret, _ = match.groups()
            if call == 'execve' and args.startswith('"/work/workload",') and int(ret) == 0:
                known.add(pid)
            owner = 'workload' if pid in known else 'unattributed'
            if pid in known and call in ('clone', 'clone3', 'fork', 'vfork') and int(ret) > 0:
                known.add(ret)
        records.append({'event_id': f'{run_id}:{index}', 'pid': pid, 'attribution': owner})
    return records


def collection(raw, run_id):
    events, failures = parse_trace(raw, run_id)
    owners = attribution(raw, run_id)
    by_id = {record['event_id']:record for record in owners}
    unattributed = unsupported = identity = 0
    for event in events:
        if by_id[event['id']]['attribution'] != 'workload':
            unattributed += 1
            event['operation'] = 'unsupported'
            for field in ('host','port','path','executable'):
                event.pop(field, None)
        if event['operation'] == 'unsupported':
            unsupported += 1
        if ('path' in event and (not event['path'].startswith('/') or ' (deleted)' in event['path'])) or event.get('port') == 0:
            identity += 1
    lines = raw.decode('utf-8', 'strict').splitlines()
    truncated = sum('...' in line or '<unfinished' in line or 'resumed>' in line for line in lines
                    if not re.search(r'\+\+\+ (?:exited|killed)', line))
    return events, owners, {
        'raw_lines':len(lines), 'event_records':len(events),
        'metadata_or_blank_lines':len(lines)-len(events), 'parse_failures':failures,
        'truncated_records':truncated, 'unsupported_events':unsupported,
        'unattributed_events':unattributed, 'identity_ambiguities':identity,
        # No collector-loss counter is available: do not invent zero drops.
        'known_dropped':None, 'completeness_verified':False,
        'authoritative_target_identity':False, 'pipeline_status':'BLOCK'}


def enforce_collection(payload):
    try:
        doc = json.loads(payload)
        coverage = doc['coverage']
        if coverage.get('complete') is not True or any(
            type(coverage.get(key)) is not int or coverage[key] != 0
            for key in ('dropped','parse_failures')):
            raise Blocked('collection_incomplete')
        for event in doc['events']:
            if event['operation'] not in ('connect','read','write','delete','exec') or event['result'] in ('unknown','attempted'):
                raise Blocked('collection_ambiguous')
            if ('path' in event and (not event['path'].startswith('/') or ' (deleted)' in event['path'])) or event.get('port') == 0:
                raise Blocked('target_identity_ambiguous')
    except (ValueError, TypeError, KeyError, AttributeError):
        raise Blocked('collection_contract_invalid') from None
    # Producer complete=true cannot attest loss-free collection or finalize
    # mapping. Until independently verified collection exists, no ledger write.
    raise Blocked('adapter_pending_spike')


def bridge(payload_path, binding, preview, database, now):
    """Protected caller passes binding; files are not a remote trust authority."""
    path = Path(payload_path)
    with path.open('rb') as f:
        payload = f.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise Blocked('payload_resource_limit')
    # Go preview reads a private snapshot, eliminating file substitution between
    # local digest check and preview input read. No targets are printed.
    if digest(payload) != binding.get('payload_digest'):
        raise Blocked('payload_binding_mismatch')
    with tempfile.TemporaryDirectory(prefix='cap-preview-') as tmp:
        snapshot = Path(tmp) / 'payload.json'
        context = Path(tmp) / 'binding.json'
        snapshot.write_bytes(payload)
        context.write_text(json.dumps(binding))
        snapshot.chmod(0o600); context.chmod(0o600)
        try:
            proc = subprocess.run([str(preview), '--payload', str(snapshot), '--binding', str(context)],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                                  env={'PATH':'/usr/bin:/bin','LANG':'C'})
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked('preview_unavailable') from None
        if proc.returncode != 0:
            raise Blocked('preview_rejected')
        try:
            report = json.loads(proc.stdout)
            if report.get('authorization_ready') is not False:
                raise Blocked('unexpected_authorization')
        except (ValueError, AttributeError):
            raise Blocked('preview_invalid_result') from None
    enforce_collection(payload)
    raise Blocked('adapter_pending_spike')


def wait_with_cleanup(process, seconds):
    try:
        process.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BYTES, MAX_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def commit_output(output, files):
    output = Path(output)
    with tempfile.TemporaryDirectory(prefix='.cap-stage-', dir=output.parent) as staging:
        for name, data in files.items():
            target = Path(staging) / name
            with target.open('xb') as f:
                os.chmod(target, 0o600)
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        # Reserve destination without overwriting existing files/symlinks.
        output.mkdir(mode=0o700, exist_ok=False)
        os.replace(staging, output)


def collect(output):
    runtime = probe()
    if any(value != 'available' for value in runtime.values()):
        raise Blocked('runtime_prerequisite_blocked')
    output = Path(output)
    # New private output only: avoid overwriting prior run/artifacts.
    if output.exists() or output.is_symlink():
        raise Blocked('output_exists')
    with tempfile.TemporaryDirectory(prefix='cap-controlled-') as scratch:
        root = Path(scratch)
        source = Path(__file__).with_name('workload.c').read_bytes()
        (root / 'workload.c').write_bytes(source)
        p = subprocess.run(['cc', '-O0', '-o', str(root / 'workload'), str(root / 'workload.c')],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
                           env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        if p.returncode:
            raise Blocked('workload_build_failed')
        artifact = (root / 'workload').read_bytes()
        artifact_hash = digest(artifact)
        (root / 'workload').chmod(0o500)
        run_id = str(uuid.uuid4())
        started = dt.datetime.now(dt.timezone.utc)
        # All host mounts read-only except disposable /work; network isolated.
        command = ['strace', '-f', '-qq', '-ttt', '-yy', '-s', '256', '-o', str(root / 'trace'),
                   *sandbox_args(root), '/work/workload']
        status, blocked = 'completed', None
        try:
            p = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, preexec_fn=limits, start_new_session=True,
                                 env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
            wait_with_cleanup(p, 5)
            if p.returncode:
                status, blocked = 'failed', 'workload_or_collector_failed'
        except subprocess.TimeoutExpired:
            status, blocked = 'failed', 'run_timeout'
        ended = dt.datetime.now(dt.timezone.utc)
        if digest((root / 'workload').read_bytes()) != artifact_hash:
            raise Blocked('artifact_changed')
        raw = (root / 'trace').read_bytes() if (root / 'trace').exists() else b''
        events, owners, loss = collection(raw, run_id)
        failures = loss['parse_failures']
        analyzer = {'name': 'controlled-strace-poc', 'version': 'proposed-0.1'}
        doc = {'version': 'raw-event-proposed-0.1', 'run_id': run_id, 'artifact_digest': artifact_hash,
               'analyzer': analyzer, 'phases': [{'name': 'controlled', 'status': status}],
               # Textual strace cannot attest loss-free whole-system coverage.
               'coverage': {'complete': False, 'dropped': 0, 'parse_failures': failures}, 'events': events}
        payload = json.dumps(doc, sort_keys=True).encode()
        if len(payload) > MAX_BYTES:
            raise Blocked('payload_resource_limit')
        binding = {'run_id': run_id, 'artifact_digest': artifact_hash, 'analyzer': analyzer,
                   'payload_digest': digest(payload), 'trace_digest': digest(raw),
                   'source_digest': digest(source), 'started_at': started.isoformat(), 'ended_at': ended.isoformat()}
        commit_output(output, {
            'payload.json': payload, 'binding.json': json.dumps(binding).encode(),
            'raw.trace': raw, 'attribution.json': json.dumps(owners).encode(),
            'loss-accounting.json': json.dumps(loss).encode(),
            'report.json': json.dumps({'authorization_ready':False, 'complete':False,
                'pipeline_status':'BLOCK', 'blocker':blocked or 'collection_incomplete'}).encode()})
        return {'authorization_ready': False, 'pipeline_status':'BLOCK', 'blocker':'collection_incomplete', 'status': status, 'events': len(events), 'coverage_complete': False}


def main():
    parser = argparse.ArgumentParser(description='Controlled Linux collector PoC; no authorization')
    parser.add_argument('mode', choices=['probe', 'collect', 'pipeline'])
    parser.add_argument('--output')
    parser.add_argument('--preview')
    parser.add_argument('--ledger')
    args = parser.parse_args()
    try:
        if args.mode == 'probe':
            print(json.dumps({'runtime': probe(), 'authorization_ready': False}))
        else:
            if not args.output:
                raise Blocked('output_required')
            if args.mode == 'pipeline' and (not args.preview or not args.ledger):
                raise Blocked('pipeline_arguments_required')
            result = collect(args.output)
            if args.mode == 'pipeline':
                if not args.preview or not args.ledger:
                    raise Blocked('pipeline_arguments_required')
                binding = json.loads((Path(args.output)/'binding.json').read_bytes())
                result = bridge(Path(args.output)/'payload.json', binding, args.preview, args.ledger, dt.datetime.now(dt.timezone.utc))
            print(json.dumps(result))
            if result.get('pipeline_status') == 'BLOCK':
                return 2
    except (Blocked, OSError, subprocess.SubprocessError) as err:
        reason = str(err) if isinstance(err, Blocked) else 'collector_io_or_process_failed'
        print(json.dumps({'authorization_ready': False, 'pipeline_status':'BLOCK', 'blocker': reason}))
        return 2
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
