"""Review supplied PAM stack structure and lockout/history declarations."""
import posixpath
import re
import shlex
from .common import InputError, Report, filemap, logical_lines, mapping, string

LIMITS=['Does not simulate PAM authentication; control jumps, sufficient short circuits and unknown modules are OPEN, never a proof of effective lockout.',
 'Only supplied pam.d service files plus faillock/pwhistory config are inspected. NSS, distribution include order, authselect generation and module runtime behavior remain OPEN.',
 'Policy values are explicit project choices. Authentication compatibility and recovery access require host validation.']
TYPES={'auth','account','password','session'};CONTROLS={'required','requisite','sufficient','optional','include','substack'}
KNOWN={'pam_unix.so','pam_faillock.so','pam_pwhistory.so','pam_deny.so','pam_permit.so','pam_env.so','pam_limits.so','pam_nologin.so','pam_localuser.so','pam_systemd.so','pam_loginuid.so','pam_succeed_if.so','pam_keyinit.so','pam_umask.so'}

def config(text,label):
    values={}
    for number,raw in logical_lines(text):
        line=raw.split('#',1)[0].strip()
        if not line:continue
        match=re.fullmatch(r'([a-z_]+)\s*(?:=\s*(\S+))?',line)
        if not match:raise InputError('malformed '+label+' at line '+str(number))
        values[match[1]]=match[2] if match[2] is not None else True
    return values

def numeric(value,label):
    if isinstance(value,str) and len(value)<=9 and value.isdigit():return int(value)
    raise InputError(label+' must be a bounded nonnegative integer string')

def analyze(snapshot):
    mapping(snapshot,'snapshot');data=filemap(snapshot.get('services'),'services');service=string(snapshot.get('service'),'service')
    report=Report('PamStackAudit','Complete supplied service include graph and supported lockout/history/password policy declarations')
    entries=[];trail=[];budget=0
    def visit(name,restrict=None,substack=False):
        nonlocal budget
        budget+=1
        if budget>10000:raise InputError('PAM expansion budget exceeded')
        if name in trail or len(trail)>=32:report.add('include_graph','OPEN',name,'Cycle or depth limit');return
        if name not in data:report.add('include_graph','OPEN',name,'Missing included service');return
        trail.append(name)
        for number,raw in logical_lines(data[name]):
            budget+=1
            if budget>10000:raise InputError('PAM expansion budget exceeded')
            line=raw.split('#',1)[0].strip();where=name+':'+str(number)
            if not line:continue
            if line.startswith('@include '):
                target=line.split(None,1)[1];report.add('distribution_include','OPEN',where,'@include is a distribution extension');visit(target,restrict);continue
            match=re.fullmatch(r'(-?(?:auth|account|password|session))\s+(\[[^\]]+\]|\S+)\s+(\S+)(?:\s+(.*))?',line)
            if not match:report.add('syntax','OPEN',where,'Unrecognized PAM configuration line');continue
            type_,control,module,args=match.groups();type_=type_.lstrip('-')
            if restrict and type_!=restrict:continue
            if control in ('include','substack'):
                if control=='substack':report.add('control_semantics','OPEN',where,'Substack action boundaries not simulated')
                visit(module,type_,control=='substack');continue
            if control.startswith('[') or control in ('sufficient','optional'):
                report.add('control_semantics','OPEN',where,'Jump/short-circuit/optional control is not simulated')
            elif control not in CONTROLS:report.add('control_semantics','OPEN',where,'Unknown control')
            module=posixpath.basename(module)
            if module not in KNOWN:report.add('module','OPEN',where,'Unknown module '+module)
            try:arguments=shlex.split(args or '')
            except ValueError as exc:raise InputError(str(exc)) from exc
            options={};flags=set()
            for token in arguments:
                if '=' in token:
                    key,value=token.split('=',1);options[key]=value
                else:flags.add(token)
            entries.append(dict(type=type_,control=control,module=module,options=options,flags=flags,where=where))
        trail.pop()
    visit(service)
    lock=config(string(snapshot.get('faillock_conf',''),'faillock_conf'),'faillock_conf')
    history=config(string(snapshot.get('pwhistory_conf',''),'pwhistory_conf'),'pwhistory_conf')
    for entry in entries:
        where=entry['where'];module=entry['module'];flags=entry['flags'];options=entry['options']
        if module=='pam_permit.so' and entry['type'] in ('auth','account','password'):
            report.add('permissive_module','FAIL',where,'Unconditional permissive module requires review')
        if module=='pam_unix.so':
            report.check('null_password','nullok' not in flags and 'nullok_secure' not in flags,where,'Null-password acceptance')
            if entry['type']=='password':
                weak={'md5','bigcrypt','des','sha256'};report.check('password_hash',not weak.intersection(flags),where,'Legacy password hash declaration')
                if not {'yescrypt','sha512','blowfish'}.intersection(flags):report.add('password_hash','OPEN',where,'Implicit distro password hash not inferred')
        if module=='pam_faillock.so':
            effective={**lock,**options,**{x:True for x in flags}}
            report.check('lockout_control',entry['control'] in ('required','requisite'),where,'Lockout module required/requisite')
            for key,minimum,maximum in [('deny',1,5),('fail_interval',900,None),('unlock_time',900,None)]:
                if key not in effective:report.add('lockout_policy','OPEN',where,'Missing explicit '+key);continue
                value=numeric(effective[key],key);report.check('lockout_policy',value>=minimum and (maximum is None or value<=maximum),where,key+'='+str(value))
            report.check('root_lockout',effective.get('even_deny_root') is True,where,'Root lockout explicitly requested')
        if module=='pam_pwhistory.so' and entry['type']=='password':
            effective={**history,**options,**{x:True for x in flags}}
            if 'remember' in effective:report.check('password_history',numeric(effective['remember'],'remember')>=5,where,'At least five historical passwords')
            else:report.add('password_history','OPEN',where,'Missing explicit remember')
            report.check('history_control',entry['control'] in ('required','requisite'),where,'History must be mandatory')
            report.check('history_root',effective.get('enforce_for_root') is True,where,'History covers root')
    auth=[x for x in entries if x['type']=='auth'];locks=[x for x in auth if x['module']=='pam_faillock.so']
    for mode in ('preauth','authfail'):
        report.check('lockout_stage',any(mode in x['flags'] for x in locks),service,'Required declaration for '+mode)
    if locks:report.add('lockout_flow','OPEN',service,'Presence does not prove failure/success routing; mandatory runtime authentication-flow validation')
    else:report.add('lockout_flow','OPEN',service,'No lockout module supplied')
    if not any(x['type']=='password' and x['module']=='pam_pwhistory.so' for x in entries):report.add('password_history','OPEN',service,'No password history module')
    if not entries:report.add('coverage','OPEN',service,'No assessable PAM entries')
    return report.finish(LIMITS)
