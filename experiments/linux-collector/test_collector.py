import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('collector',Path(__file__).with_name('collector.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)

class Tests(unittest.TestCase):
 def test_results_and_direction(self):
  raw=b'1760000000.0 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)\n1760000000.1 bind(3, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
  e,n=c.parse_trace(raw,'r');self.assertEqual(n,0);self.assertEqual(e[0]['result'],'failed');self.assertEqual(e[0]['operation'],'connect');self.assertEqual(e[0]['port'],443);self.assertEqual(e[1]['operation'],'bind');self.assertEqual(e[1]['port'],0)
 def test_content_access_and_exec(self):
  raw=b'1760000000.0 read(3</work/x>, "a", 1) = 1\n1760000000.1 write(3</work/x>, "a", 1) = -1 EBADF (Bad file descriptor)\n1760000000.2 execve("/work/tool", [], 0x0 /* 0 vars */) = 0\n1760000000.3 unlink("missing") = -1 ENOENT (No such file)\n'
  e,n=c.parse_trace(raw,'r');self.assertEqual(n,0);self.assertEqual([x['operation'] for x in e],['read','write','exec','delete']);self.assertEqual(e[1]['result'],'failed')
 def test_no_silent_drop(self):
  e,n=c.parse_trace(b'garbled\n1760000000.0 stat("x", {}) = 0\n1760000000.1 read(3, "a", 1) = 1\n','r');self.assertEqual(len(e),3);self.assertEqual(n,2);self.assertTrue(all(x['operation']=='unsupported' for x in e))
 def test_truncation_and_inprogress(self):
  e,n=c.parse_trace(b'1760000000.0 execve("/tool"..., [], 0x0) = 0\n1760000000.1 connect(3, {sin_port=htons(443), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)\n','r');self.assertEqual(n,1);self.assertEqual(e[0]['operation'],'unsupported');self.assertEqual(e[1]['result'],'attempted')
 def test_resource_limits(self):
  for b in [b'x'*(c.MAX_BYTES+1),b'\xff',b'bad\n'*1025]:
   with self.assertRaises(c.Blocked):c.parse_trace(b,'r')
 def envelope(self):
  now=dt.datetime(2026,10,8,tzinfo=dt.timezone.utc)
  doc={'run_id':'r','artifact_digest':'a'*64,'analyzer':{'name':'test','version':'1'},'events':[{'observed_at':now.isoformat()}]}
  b=json.dumps(doc).encode();bind={**{k:doc[k] for k in ['run_id','artifact_digest','analyzer']},'payload_digest':c.digest(b),'started_at':now.isoformat(),'ended_at':now.isoformat()};return b,bind,now
 def test_binding_replay_freshness(self):
  with tempfile.TemporaryDirectory() as tmp:
   db=str(Path(tmp)/'runs.sqlite');b,bind,now=self.envelope()
   for field in ['payload_digest','artifact_digest','run_id','analyzer']:
    bad={**bind,field:'other'}
    with self.assertRaises(c.Blocked):c.accept(b,bad,db,now)
   for delta in [-1,301]:
    with self.assertRaises(c.Blocked):c.accept(b,bind,db,now+dt.timedelta(seconds=delta))
   self.assertFalse(c.accept(b,bind,db,now)['authorization_ready'])
   with self.assertRaisesRegex(c.Blocked,'replayed_run'):c.accept(b,bind,db,now)
 def test_outside_run_does_not_consume(self):
  with tempfile.TemporaryDirectory() as tmp:
   b,bind,now=self.envelope();bad={**bind,'started_at':(now+dt.timedelta(seconds=1)).isoformat()}
   with self.assertRaisesRegex(c.Blocked,'invalid_run_time'):c.accept(b,bad,str(Path(tmp)/'runs'),now)
   c.accept(b,bind,str(Path(tmp)/'runs'),now)
 def test_runtime_blocked_no_fallback(self):
  with tempfile.TemporaryDirectory() as tmp,patch.object(c,'probe',return_value={'tracing':'blocked','sandbox':'available','compiler':'available'}):
   target=Path(tmp)/'output'
   with self.assertRaisesRegex(c.Blocked,'runtime_prerequisite_blocked'):c.collect(target)
   self.assertFalse(target.exists())
 def test_secret_errors(self):
  with self.assertRaises(c.Blocked) as err:c.parse_trace(b'\xffSECRET','r')
  self.assertNotIn('SECRET',str(err.exception))

class HardeningTests(unittest.TestCase):
 def test_attribution_and_no_retroactive_ownership(self):
  trace=b'10 1760000000.0 read(3</runtime/file>, "x", 1) = 1\n10 1760000000.1 execve("/work/workload", [], 0x0) = 0\n10 1760000000.2 clone(flags=SIGCHLD) = 11\n11 1760000000.3 write(3</work/x>, "x", 1) = 1\n12 1760000000.4 execve("/work/workload", [], 0x0) = -1 ENOENT (No such file)\n'
  owners=c.attribution(trace,'r');self.assertEqual([x['attribution'] for x in owners],['unattributed','workload','workload','workload','unattributed'])
 def test_sandbox_mounts(self):
  args=c.sandbox_args('/private/work');self.assertNotIn('--ro-bind / /',' '.join(args));self.assertIn('--unshare-all',args);self.assertIn('--tmpfs',args);self.assertNotIn('/home',args);self.assertNotIn('/etc',args)
 def test_missing_or_naive_binding(self):
  b,bind,now=Tests().envelope()
  with tempfile.TemporaryDirectory() as tmp:
   for bad in [{},None,{**bind,'ended_at':'2026-10-08T00:00:00'}]:
    with self.assertRaises(c.Blocked):c.accept(b,bad,str(Path(tmp)/'db'),now)
 def test_private_replay_store(self):
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'db';path.symlink_to(Path(tmp)/'other')
   with self.assertRaises(c.Blocked):c.private_ledger(path)
 def test_real_go_preview_bridge_with_synthetic_payload(self):
  import os
  executable=os.environ.get('CAP_PREVIEW_TEST_BIN')
  if not executable:self.skipTest('set CAP_PREVIEW_TEST_BIN for real Go bridge')
  with tempfile.TemporaryDirectory() as tmp:
   doc=json.loads(Path(__file__).parents[2].joinpath('adapters/raw-event-preview/testdata/synthetic-connect.json').read_bytes())
   doc['phases']=[{'name':'controlled','status':'completed'}];doc['events'][0]['phase']='controlled'
   b=json.dumps(doc).encode();now=dt.datetime(2026,10,8,tzinfo=dt.timezone.utc)
   bind={**{k:doc[k] for k in ['run_id','artifact_digest','analyzer']},'payload_digest':c.digest(b),'started_at':now.isoformat(),'ended_at':now.isoformat()}
   path=Path(tmp)/'payload';path.write_bytes(b);db=str(Path(tmp)/'db')
   with self.assertRaisesRegex(c.Blocked,'adapter_pending_spike'):c.bridge(path,bind,executable,db,now)
   self.assertFalse(Path(db).exists())
   path.write_bytes(b+b' ')
   with self.assertRaisesRegex(c.Blocked,'payload_binding_mismatch'):c.bridge(path,bind,executable,db,now)
 def test_preview_failure_does_not_consume_run(self):
  b,bind,now=Tests().envelope()
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'payload';p.write_bytes(b)
   with self.assertRaisesRegex(c.Blocked,'preview_rejected'):c.bridge(p,bind,'/bin/false',str(Path(tmp)/'db'),now)
   self.assertFalse((Path(tmp)/'db').exists())



class OutputTests(unittest.TestCase):
 def test_atomic_output_no_overwrite(self):
  with tempfile.TemporaryDirectory() as tmp:
   target=Path(tmp)/'run';c.commit_output(target,{'report.json':b'{}','raw.trace':b'data'})
   self.assertEqual((target/'raw.trace').read_bytes(),b'data')
   self.assertEqual((target/'raw.trace').stat().st_mode & 0o777,0o600)
   with self.assertRaises(FileExistsError):c.commit_output(target,{'raw.trace':b'changed'})
   self.assertEqual((target/'raw.trace').read_bytes(),b'data')
 def test_write_failure_no_partial_run(self):
  with tempfile.TemporaryDirectory() as tmp,patch('os.fsync',side_effect=OSError('disk full SECRET')):
   target=Path(tmp)/'run'
   with self.assertRaises(OSError):c.commit_output(target,{'raw.trace':b'data'})
   self.assertFalse(target.exists());self.assertEqual(list(Path(tmp).iterdir()),[])
 def test_pid_exit_reuse_unknown(self):
  raw=b'10 1760000000.0 execve("/work/workload", [], 0x0) = 0\n10 1760000000.1 +++ exited with 0 +++\n10 1760000000.2 read(3</other>, "x", 1) = 1\n'
  self.assertEqual(c.attribution(raw,'r')[-1]['attribution'],'unattributed')

class TimeoutTests(unittest.TestCase):
 def test_timeout_kills_group_and_reaps(self):
  from unittest.mock import Mock
  p=Mock(pid=123);p.wait.side_effect=[c.subprocess.TimeoutExpired('controlled',1),0]
  with patch.object(c.os,'killpg') as kill:
   with self.assertRaises(c.subprocess.TimeoutExpired):c.wait_with_cleanup(p,1)
   kill.assert_called_once_with(123,c.signal.SIGKILL);self.assertEqual(p.wait.call_count,2)
 def test_exit_race_still_reaps(self):
  from unittest.mock import Mock
  p=Mock(pid=123);p.wait.side_effect=[c.subprocess.TimeoutExpired('controlled',1),0]
  with patch.object(c.os,'killpg',side_effect=ProcessLookupError):
   with self.assertRaises(c.subprocess.TimeoutExpired):c.wait_with_cleanup(p,1)
   self.assertEqual(p.wait.call_count,2)

class LossTests(unittest.TestCase):
 def test_loss_visible_and_no_action_for_unattributed(self):
  raw=b'10 1760000000.0 read(3</runtime/x>, "x", 1) = 1\n10 1760000000.1 execve("/work/workload", [], 0x0) = 0\n10 1760000000.2 read(3</work/x>, "x"..., 1) = 1\ngarbled\n'
  events,owners,loss=c.collection(raw,'r')
  self.assertEqual(len(events),4);self.assertEqual(events[0]['operation'],'unsupported')
  self.assertEqual(loss['truncated_records'],1);self.assertEqual(loss['parse_failures'],2)
  self.assertGreaterEqual(loss['unattributed_events'],2);self.assertIsNone(loss['known_dropped'])
  self.assertFalse(loss['completeness_verified']);self.assertEqual(loss['pipeline_status'],'BLOCK')
 def test_relative_deleted_and_port_zero_identity(self):
  raw=b'10 1760000000.0 execve("/work/workload", [], 0x0) = 0\n10 1760000000.1 unlink("relative") = 0\n10 1760000000.2 read(3</work/x (deleted)>, "x", 1) = 1\n10 1760000000.3 connect(3, {sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
  e,_,loss=c.collection(raw,'r');self.assertEqual(e[-1]['port'],0);self.assertGreaterEqual(loss['identity_ambiguities'],3)
 def test_incomplete_input_never_consumes_run(self):
  import os
  executable=os.environ.get('CAP_PREVIEW_TEST_BIN')
  if not executable:self.skipTest('real Go preview needed')
  doc=json.loads(Path(__file__).parents[2].joinpath('adapters/raw-event-preview/testdata/synthetic-connect.json').read_bytes())
  with tempfile.TemporaryDirectory() as tmp:
   for key,value in [('complete',False),('dropped',1),('parse_failures',1)]:
    current=json.loads(json.dumps(doc));current['coverage'][key]=value
    b=json.dumps(current).encode();p=Path(tmp)/'payload';p.write_bytes(b)
    now=dt.datetime(2026,10,8,tzinfo=dt.timezone.utc);bind={**{k:current[k] for k in ['run_id','artifact_digest','analyzer']},'payload_digest':c.digest(b),'started_at':now.isoformat(),'ended_at':now.isoformat()}
    with self.assertRaisesRegex(c.Blocked,'collection_incomplete'):c.bridge(p,bind,executable,str(Path(tmp)/'db'),now)
    self.assertFalse((Path(tmp)/'db').exists())

class AdditionalLossTests(unittest.TestCase):
 def test_invalid_ip_not_present(self):
  raw=b'10 1760000000.0 execve("/work/workload", [], 0x0) = 0\n10 1760000000.1 connect(3, {sin_port=htons(443), sin_addr=inet_addr("999.0.0.1")}, 16) = 0\n'
  events,_,loss=c.collection(raw,'r');self.assertEqual(events[-1]['operation'],'unsupported');self.assertEqual(loss['parse_failures'],1)
 def test_ipv6_spelling_port_preserved(self):
  raw=b'10 1760000000.0 execve("/work/workload", [], 0x0) = 0\n10 1760000000.1 connect(3, {sin6_port=htons(8443), inet_pton(AF_INET6, "2001:DB8::1", &sin6_addr)}, 28) = 0\n'
  e,_,_=c.collection(raw,'r');self.assertEqual(e[-1]['host'],'2001:DB8::1');self.assertEqual(e[-1]['port'],8443)
 def test_unsupported_and_unknown_action_gate(self):
  for operation,result in [('future','succeeded'),('connect','unknown'),('bind','succeeded')]:
   doc={'coverage':{'complete':True,'dropped':0,'parse_failures':0},'events':[{'operation':operation,'result':result}]}
   with self.assertRaisesRegex(c.Blocked,'collection_ambiguous'):c.enforce_collection(json.dumps(doc).encode())
 def test_bool_loss_counter_is_invalid(self):
  doc={'coverage':{'complete':True,'dropped':False,'parse_failures':0},'events':[]}
  with self.assertRaisesRegex(c.Blocked,'collection_incomplete'):c.enforce_collection(json.dumps(doc).encode())

if __name__=='__main__':unittest.main()
