# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import unittest
from pam_stack_audit import analyze
from pam_stack_audit.common import InputError

class PamTests(unittest.TestCase):
    def good(self):return {'service':'login','services':{'login':'auth required pam_faillock.so preauth\nauth required pam_unix.so\nauth required pam_faillock.so authfail\npassword required pam_pwhistory.so remember=5 enforce_for_root\npassword required pam_unix.so yescrypt'},'faillock_conf':'deny=5\nfail_interval=900\nunlock_time=900\neven_deny_root'}
    def test_declared_policy_still_open(self):
        r=analyze(self.good());self.assertEqual(r['status'],'OPEN');self.assertEqual(r['counts']['FAIL'],0)
    def test_null_password(self):
        s=self.good();s['services']['login']+='\nauth required pam_unix.so nullok';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_permissive_module(self):
        s=self.good();s['services']['login']+='\nauth sufficient pam_permit.so';self.assertEqual(analyze(s)['status'],'FAIL')
    def test_missing_auth_stage(self):
        s=self.good();s['services']['login']=s['services']['login'].replace('auth required pam_faillock.so authfail','');self.assertEqual(analyze(s)['status'],'FAIL')
    def test_include_resolution(self):
        s=self.good();s['services']['policy']=s['services']['login'];s['services']['login']='auth include policy\npassword include policy';self.assertEqual(analyze(s)['counts']['FAIL'],0)
    def test_cycle(self):self.assertEqual(analyze({'service':'a','services':{'a':'auth include a'}})['status'],'FAIL')
    def test_bracket_control_open(self):
        s=self.good();s['services']['login']+='\nauth [success=1 default=bad] pam_unix.so';self.assertTrue(any(f['check']=='control_semantics' for f in analyze(s)['findings']))
    def test_option_override(self):
        s=self.good();s['services']['login']=s['services']['login'].replace('preauth','preauth deny=10');self.assertEqual(analyze(s)['status'],'FAIL')
    def test_large_number(self):
        s=self.good();s['faillock_conf']='deny='+'9'*5000
        with self.assertRaises(InputError):analyze(s)
    def test_wrong_services_type(self):
        with self.assertRaises(InputError):analyze({'service':'a','services':[]})
