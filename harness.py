"""Controlled live harness: PASS means verified collection plus pipeline BLOCK.
It never means package authorization. Exit 0/2/1 = PASS/BLOCKED/FAIL.
"""
import argparse
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile

spec=importlib.util.spec_from_file_location('cap_collector',Path(__file__).with_name('collector.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

def exit_code(status):
    return {'PASS':0,'BLOCKED':2,'FAIL':1}[status]

def result(status,reason,trace=False,checks=None):
    return {'status':status,'reason':reason,'genuine_trace_collected':trace,
            'authorization_ready':False,'pipeline_status':'BLOCK','checks':checks or {}}

def bounded(path):
    with Path(path).open('rb') as f:
        data=f.read(c.MAX_BYTES+1)
    if len(data)>c.MAX_BYTES:raise c.Blocked('harness_resource_limit')
    return data

def controlled_checks(raw, owners, run_id):
    """Fixed boolean diagnostics only; retain the exact original PASS criteria."""
    checks={key:False for key in (
        'controlled_exec_observed','forbidden_file_attempt_observed','unapproved_bind_attempt_observed',
        'exec_raw_marker','file_raw_marker','bind_raw_marker',
        'exec_parsed_marker','file_parsed_marker','bind_parsed_marker',
        'exec_attributed_marker','file_attributed_marker','bind_attributed_marker',
        'bind_loopback_present')}
    by_id={entry['event_id']:entry for entry in owners}
    for index,line in enumerate(raw.decode('utf-8').splitlines()):
        markers={'exec':'execve("/work/workload",' in line,
                 'file':'"/restricted/forbidden.txt"' in line,
                 'bind':'bind(' in line and 'htons(12345)' in line}
        for key,present in markers.items():
            checks[key+'_raw_marker'] |= present
        match=c.LINE.fullmatch(line)
        if not match:continue
        _,call,args,ret,_=match.groups()
        attributed=by_id.get(f'{run_id}:{index}',{}).get('attribution')=='workload'
        for key,present in markers.items():
            checks[key+'_parsed_marker'] |= present
            checks[key+'_attributed_marker'] |= present and attributed
        if not attributed:continue
        checks['controlled_exec_observed'] |= call=='execve' and args.startswith('"/work/workload",') and int(ret)==0
        checks['forbidden_file_attempt_observed'] |= call=='openat' and '"/restricted/forbidden.txt"' in args and int(ret)<0
        checks['bind_loopback_present'] |= call=='bind' and 'htons(12345)' in args and '127.0.0.1' in args
        checks['unapproved_bind_attempt_observed'] |= call=='bind' and 'htons(12345)' in args and '127.0.0.1' in args
    return checks


def run(preview,probe_fn=None,collect_fn=None):
    probe_fn=probe_fn or c.probe;collect_fn=collect_fn or c.collect
    verified_trace=False
    try:
        runtime=probe_fn()
        if set(runtime)!={'tracing','sandbox','compiler'}:
            return result('FAIL','invalid_preflight_report')
        if any(value!='available' for value in runtime.values()):
            return result('BLOCKED','runtime_prerequisite_blocked')
        with tempfile.TemporaryDirectory(prefix='cap-harness-') as tmp:
            output=Path(tmp)/'run';state=collect_fn(output)
            raw=bounded(output/'raw.trace')
            if not raw:
                return result('FAIL','empty_trace')
            if state.get('status')!='completed':
                return result('FAIL','controlled_workload_failed')
            binding=json.loads(bounded(output/'binding.json'))
            payload=bounded(output/'payload.json')
            if c.digest(raw)!=binding.get('trace_digest') or c.digest(payload)!=binding.get('payload_digest'):
                return result('FAIL','collected_bytes_mismatch')
            if c.digest(Path(__file__).with_name('workload.c').read_bytes())!=binding.get('source_digest'):
                return result('FAIL','controlled_source_mismatch')
            events,owners,loss=c.collection(raw,binding['run_id'])
            checks=controlled_checks(raw,owners,binding['run_id'])
            checks['event_records']=len(events)
            checks['parse_failures']=loss['parse_failures']
            checks['unattributed_events']=loss['unattributed_events']
            if not all(checks[key] for key in ('controlled_exec_observed','forbidden_file_attempt_observed','unapproved_bind_attempt_observed')):
                return result('FAIL','controlled_events_missing',checks=checks)
            verified_trace=True
            ledger=Path(tmp)/'ledger.sqlite'
            try:
                c.bridge(output/'payload.json',binding,preview,ledger,dt.datetime.now(dt.timezone.utc))
            except c.Blocked as err:
                if str(err)!='collection_incomplete':
                    return result('FAIL','unexpected_pipeline_result',True)
            else:
                return result('FAIL','pipeline_did_not_block',True)
            if ledger.exists():
                return result('FAIL','blocked_run_consumed',True)
            return result('PASS','live_collection_and_closed_mapping_verified',True,{
                'controlled_exec_observed':True,'forbidden_file_attempt_observed':True,
                'unapproved_bind_attempt_observed':True,'preview_executed':True,
                'incomplete_pipeline_blocked':True,'ledger_untouched':True,
                'event_records':len(events),'unsupported_events':loss['unsupported_events']})
    except c.Blocked as err:
        if str(err)=='runtime_prerequisite_blocked':
            return result('BLOCKED','runtime_prerequisite_blocked')
        return result('FAIL','collector_or_validation_blocker',verified_trace)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,c.subprocess.SubprocessError):
        return result('FAIL','harness_io_or_validation_failed',verified_trace)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preview',required=True)
    parser.add_argument('--report')
    args=parser.parse_args()
    report=run(args.preview)
    if args.report:
        try:
            with Path(args.report).open('x') as f:
                c.os.chmod(args.report,0o600)
                json.dump(report,f,indent=2);f.write('\n')
        except OSError:
            report=result('FAIL','harness_report_write_failed',report['genuine_trace_collected'])
    print(json.dumps(report))
    return exit_code(report['status'])

if __name__=='__main__':raise SystemExit(main())
