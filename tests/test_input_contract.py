import unittest,json,tempfile,subprocess,sys
from pathlib import Path
PACKAGE="pam_stack_audit"
class InputContractTests(unittest.TestCase):
    def test_surrogate_keys_values_and_duplicate_keys_fail_without_traceback(self):
        cases=[b'{"unknown":1e999}',b'{"unknown":"\\ud800"}',b'{"\\ud800":1}',b'{"\\ud800":1,"\\ud800":2}']
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.json"
            for raw in cases:
                path.write_bytes(raw)
                result=subprocess.run([sys.executable,"-m",PACKAGE,str(path)],capture_output=True,timeout=10)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"],"ERROR")
                self.assertNotIn(b"Traceback",result.stderr)
