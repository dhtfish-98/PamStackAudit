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

    def test_missing_safe_open_flags_returns_controlled_error(self):
        import io,contextlib
        from unittest.mock import patch
        from pam_stack_audit.common import run
        for missing in ('O_NOFOLLOW','O_NONBLOCK'):
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'input.json';path.write_text('{}')
                output=io.StringIO()
                with patch.object(__import__('os'),missing,None,create=True),patch.object(sys,'argv',['audit',str(path)]),contextlib.redirect_stdout(output):
                    exit_code=run(lambda snapshot: self.fail('must not evaluate input when safe flags are unavailable'))
                self.assertEqual(exit_code,2)
                self.assertEqual(json.loads(output.getvalue())['status'],'ERROR')
