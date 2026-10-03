> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# PamStackAudit

Version **0.1.2**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

PAM stack and lockout policy snapshot audit. Complete independent **new scope**, not the whole upstream system rewritten.

Input: `{"service":"login","services":{"login":"PAM text","common-auth":"PAM text"},"faillock_conf":"...","pwhistory_conf":"..."}`. Entire supplied include/substack graph is inspected with cycle/depth/10000-expansion limits; mandatory/optional/bracketed control distinctions remain visible. Checks include null passwords, legacy password hash declarations, permissive auth modules, required faillock preauth/authfail stages, explicit deny/fail_interval/unlock_time values, root coverage and password history. Module options override supplied config. Unknown modules, missing files, jump/short-circuit controls, distribution includes and stack-flow effectiveness are OPEN. Even a complete clean example exits 3: presence of required lockout stages does not establish actual failure/success routing. No PAM modules are loaded, users authenticated or settings changed.

## Use and output

Install `artifacts/*.whl` and run `pam-stack-audit examples/good.json`, or `python -m pam_stack_audit examples/good.json`. Output is structured JSON with individual PASS/FAIL/OPEN evidence and aggregate counts. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. Unsupported or incomplete evidence cannot exit 0. Input is at most 2 MiB, 32 layers and 100000 nodes; duplicate keys/nonfinite numbers are rejected. The same non-following/non-blocking fd must be regular and unchanged across reading. Findings are bounded to 20000.

## Evidence and limits

`ORIGIN.md` pins exact upstream files/commit/hashes. `tests/` covers substantive parser/policy cases; `examples/expectations.json` lists expected CLI results. `VALIDATION.md` and `artifacts/validation.json` separate unit/wheel/CLI evidence from effective host behavior, upstream equivalence and CVP eligibility/approval, which remain OPEN. All processing is offline, read-only and uses supplied synthetic/public evidence.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.

Numeric declarations use bounded ASCII digits. The selected fail_interval/unlock_time policy requires 900..604800 seconds; values above the frozen module's MAX_TIME_INTERVAL are FAIL rather than being treated as accepted policy. Unicode numeric spellings are ERROR. Routing and effective authentication remain OPEN.
