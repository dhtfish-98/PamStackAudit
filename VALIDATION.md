# Current re-audit verification — 2026-10-02

Version **0.1.1**: **15 installed unittest cases PASS**. A new wheel was built and installed into a fresh, separate environment. Runtime bytes in source, wheel and installed package matched. Dependency checks and retained license bytes passed.

Wheel: `pam_stack_audit-0.1.1-py3-none-any.whl`. SHA-256: `3d5e398f7ea95f3b8bf5b1602239c82d7e80ff7e68c80b901f9fca29d0b03900`. Current machine-readable result: `REAUDIT_20261002.json`.

Reproduce with `python -m pip install .`, `python -m unittest discover -s tests -v`, and `python -m pip wheel --no-deps --wheel-dir artifacts .`. Python 3.14/macOS was exercised locally. Exact-commit GitHub checks provide separate Linux evidence; native Windows and effective deployment remain OPEN. Project scope and unsupported input behavior remain defined in README.md.

The records below are historical source/oracle/initial-installation evidence, retained for provenance. Earlier test counts, wheel hashes, versions and installation claims refer to the original release and do not validate this repaired release. Full upstream equivalence and CVP applicant qualification/approval remain OPEN.

---

# Validation

PASS: local unit tests, independent wheel build, isolated target install, import origin, and all CLI example exit codes. See `artifacts/validation.json` for commands, results and wheel SHA-256.

This confirms local Python snapshot behavior only. Effective Linux/Windows runtime protection, real-device telemetry, upstream behavioral equivalence, and CVP qualification/approval remain OPEN.
