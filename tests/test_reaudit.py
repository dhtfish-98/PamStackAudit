import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from pam_stack_audit import analyze
from pam_stack_audit.common import InputError
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,exit_code):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'input.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','pam_stack_audit',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,exit_code,r.stderr);self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_ascii_numeric_configuration_and_options(self):
        for replacement in ('unlock_time=٩٠٠','deny=٥','fail_interval=９００'):
            s=self.good();name=replacement.split('=')[0];expected={'unlock_time':'900','deny':'5','fail_interval':'900'}[name];s['faillock_conf']=s['faillock_conf'].replace(name+'='+expected,replacement)
            with self.assertRaises(InputError):analyze(s)
            self.assertEqual(self.cli(s,2)['status'],'ERROR')
        s=self.good();s['services']['login']=s['services']['login'].replace('remember=5','remember=٥')
        with self.assertRaises(InputError):analyze(s)
        self.assertEqual(self.cli(s,2)['status'],'ERROR')
    def test_frozen_faillock_time_upper_bound(self):
        for key in ('fail_interval','unlock_time'):
            for value in ('604801','999999999'):
                s=self.good();s['faillock_conf']=s['faillock_conf'].replace(key+'=900',key+'='+value)
                self.assertEqual(analyze(s)['status'],'FAIL');self.assertEqual(self.cli(s,1)['status'],'FAIL')
    def test_valid_time_bounds_keep_flow_open(self):
        for value in ('900','604800'):
            s=self.good();s['faillock_conf']=s['faillock_conf'].replace('=900','='+value)
            r=analyze(s);self.assertEqual(r['status'],'OPEN');self.assertEqual(r['counts']['FAIL'],0)
            self.assertEqual(self.cli(s,3)['status'],'OPEN')
