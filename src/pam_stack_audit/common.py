"""Bounded read-only snapshot I/O; no system collection or mutation."""
import argparse
import hashlib
import json
import math
import os
import stat
from pathlib import Path

class InputError(ValueError):
    pass

def mapping(value, label):
    if not isinstance(value, dict):
        raise InputError(label + " must be an object")
    return value

def string(value, label):
    if not isinstance(value, str) or "\x00" in value:
        raise InputError(label + " must be a NUL-free string")
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise InputError('snapshot string is not valid Unicode') from None
    return value

def sequence(value, label):
    if not isinstance(value, list) or len(value) > 10000:
        raise InputError(label + " must be a bounded array")
    return value

def filemap(value, label="files"):
    files = mapping(value, label)
    if len(files) > 1000:
        raise InputError("too many snapshot files")
    return {string(k, label): string(v, label) for k, v in files.items()}

def logical_lines(text):
    pending = ""
    start = 1
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        pending += line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        yield start, pending
        pending = ""
    if pending:
        raise InputError("unterminated line continuation")

class Report:
    def __init__(self, tool, scope):
        self.tool, self.scope, self.findings = tool, scope, []
    def add(self, check, status, evidence, message):
        if len(self.findings) >= 20000:
            raise InputError("finding budget exceeded")
        self.findings.append(dict(check=check, status=status, evidence=evidence, message=message))
    def check(self, check, ok, evidence, message):
        self.add(check, "PASS" if ok else "FAIL", evidence, message)
    def finish(self, limitations):
        if not self.findings:
            self.add("coverage", "OPEN", "", "No assessable records")
        counts = {s: sum(f["status"] == s for f in self.findings) for s in ("PASS", "FAIL", "OPEN")}
        status = "FAIL" if counts["FAIL"] else "OPEN" if counts["OPEN"] else "PASS"
        return dict(schema_version=1, tool=self.tool, scope=self.scope, status=status,
                    counts=counts, findings=self.findings, limitations=limitations)

def run(analyze):
    parser = argparse.ArgumentParser(description="Audit a supplied offline JSON snapshot; never change host settings")
    parser.add_argument("snapshot", type=Path)
    args = parser.parse_args()
    try:
        descriptor = os.open(args.snapshot, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise InputError("snapshot must be a regular non-symlink file")
            raw = stream.read(2 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if identity(before) != identity(after):
            raise InputError("snapshot changed while reading")
        if len(raw) > 2 * 1024 * 1024:
            raise InputError("snapshot exceeds 2 MiB")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise InputError("duplicate JSON key: " + key)
                result[key] = value
            return result
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                             parse_constant=lambda value: (_ for _ in ()).throw(InputError("non-finite JSON number")))
        pending = [(payload, 0)]; nodes = 0
        while pending:
            value, depth = pending.pop(); nodes += 1
            if depth > 32 or nodes > 100000:
                raise InputError("snapshot nesting or record limit exceeded")
            if isinstance(value, str):string(value,'snapshot string')
            if isinstance(value, float) and not math.isfinite(value):
                raise InputError('non-finite JSON number')
            if isinstance(value, dict):
                pending.extend((v, depth+1) for v in value.values())
                pending.extend((k, depth+1) for k in value)
            elif isinstance(value, list): pending.extend((v, depth+1) for v in value)
        report = analyze(mapping(payload, "snapshot"))
        report["input_sha256"] = hashlib.sha256(raw).hexdigest()
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        print(json.dumps(dict(schema_version=1, status="ERROR", error=str(exc)), ensure_ascii=True))
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 3}[report["status"]]
