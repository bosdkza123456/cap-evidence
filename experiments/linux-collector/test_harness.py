import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('harness',Path(__file__).with_name('harness.py'))
h=importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

class HarnessTests(unittest.TestCase):
 def test_prerequisite_blocked_not_pass(self):
  called=[]
  result=h.run('/missing',probe_fn=lambda:{'tracing':'blocked','sandbox':'blocked','compiler':'available'},collect_fn=lambda p:called.append(p))
  self.assertEqual(result['status'],'BLOCKED');self.assertFalse(called);self.assertFalse(result['genuine_trace_collected'])
 def test_empty_trace_never_pass(self):
  def fake(out):
   Path(out).mkdir();(Path(out)/'raw.trace').write_bytes(b'');return {'status':'completed'}
  result=h.run('/missing',probe_fn=lambda:{'tracing':'available','sandbox':'available','compiler':'available'},collect_fn=fake)
  self.assertEqual(result['status'],'FAIL');self.assertFalse(result['genuine_trace_collected'])
 def test_collection_error_not_runtime_skip(self):
  def fake(out):raise OSError('SECRET DISK FAILURE')
  result=h.run('/missing',probe_fn=lambda:{'tracing':'available','sandbox':'available','compiler':'available'},collect_fn=fake)
  self.assertEqual(result['status'],'FAIL');self.assertNotIn('SECRET',str(result))
 def test_exit_status_contract(self):
  self.assertEqual([h.exit_code(x) for x in ['PASS','BLOCKED','FAIL']],[0,2,1])
 def test_runtime_deterioration_is_blocked(self):
  def fake(out):raise h.c.Blocked('runtime_prerequisite_blocked')
  result=h.run('/missing',probe_fn=lambda:{'tracing':'available','sandbox':'available','compiler':'available'},collect_fn=fake)
  self.assertEqual(result['status'],'BLOCKED')

class AdditionalHarnessTests(unittest.TestCase):
 def test_missing_preflight_fields_fail(self):
  r=h.run('/missing',probe_fn=lambda:{},collect_fn=lambda p:None)
  self.assertEqual(r['status'],'FAIL')
 def test_nonempty_trace_with_invalid_hash_fails(self):
  import json
  def fake(out):
   p=Path(out);p.mkdir();(p/'raw.trace').write_bytes(b'not a real trace')
   (p/'payload.json').write_bytes(b'{}');(p/'binding.json').write_text(json.dumps({'trace_digest':'wrong','payload_digest':'wrong'}))
   return {'status':'completed'}
  r=h.run('/missing',probe_fn=lambda:{'tracing':'available','sandbox':'available','compiler':'available'},collect_fn=fake)
  self.assertEqual(r['status'],'FAIL');self.assertFalse(r['genuine_trace_collected'])
 def test_report_write_error_never_pass(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'existing';path.write_text('preserved')
   with patch('sys.argv',['harness','--preview','/missing','--report',str(path)]),patch.object(h,'run',return_value=h.result('BLOCKED','runtime_prerequisite_blocked')):
    self.assertEqual(h.main(),1)
   self.assertEqual(path.read_text(),'preserved')

if __name__=='__main__':unittest.main()
