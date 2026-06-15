<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# pip-audit Findings — vince-lam/superset

**Date:** 2026-06-15
**Branch base:** `master` @ `2734bde504` (`fix(chart): Allow Admin non-owner to save chart (#37175)`)
**Tool:** `pip-audit 2.10.1` (PyPI Advisory Database)
**Python:** 3.12.8

## How the audit was run

```bash
python -m pip install pip-audit
# Runtime deps
python -m pip_audit -r requirements/base.txt --desc
# Full dev set (superset of base.txt)
python -m pip_audit -r requirements/development.txt --desc
# Smaller files
python -m pip_audit -r RELEASING/requirements.txt --no-deps
python -m pip_audit -r superset/translations/requirements.txt --no-deps
```

> Note: `requirements/development.txt` initially failed because pip-audit's resolver
> tried to build `mysqlclient` from source. Fixed by installing system build deps:
> `sudo apt-get install -y pkg-config default-libmysqlclient-dev build-essential`.

## Summary

| File | Result |
|---|---|
| `requirements/base.txt` (runtime) | 7 vulnerabilities / 3 packages |
| `requirements/development.txt` (superset of base) | 16 vulnerabilities / 7 packages |
| `RELEASING/requirements.txt` | No known vulnerabilities |
| `superset/translations/requirements.txt` | No known vulnerabilities |

Everything in `base.txt` is also present in `development.txt`, so the 16 findings
below are the complete picture. The split below separates packages that ship in
production (runtime) from dev/build-tooling-only packages.

## Runtime dependencies (ship in production) — highest priority

### pyjwt 2.12.0 → 2.13.0 (5 advisories)
| ID | Fix | Description |
|---|---|---|
| PYSEC-2026-176 | 2.12.1 | Verifier-side algorithm allow-list bypass when `jwt.decode()` is called with a PyJWK key. Header `alg` is checked against the allow-list, but verification uses the algorithm bound to the PyJWK object — an attacker controlling a registered JWK/JWKS key can sign with a disallowed algorithm and still be accepted. Affects `PyJWKClient.get_signing_key_from_jwt(...)`. |
| PYSEC-2026-179 | 2.13.0 | When decoding JWTs supporting both asymmetric and HMAC algorithms, the library does not validate use of JSON Web Keys in the HMAC algorithm, allowing an attacker to use the issuer public key as the HMAC secret. |
| PYSEC-2026-175 | 2.13.0 | `PyJWKClient` passes its `uri` directly to `urllib.request.urlopen()` (registers `file://`, FTP, data URI handlers). Attacker-influenced `jku`/URL ingestion can cause arbitrary local file reads (SSRF on local filesystem) and broader SSRF. |
| PYSEC-2026-177 | 2.13.0 | `PyJWKClient.get_signing_key()` forces a fresh HTTP request per JWT with an unknown `kid` (taken from unverified header), with no rate limiting — unauthenticated outbound-request amplification / DoS. |
| PYSEC-2026-178 | 2.13.0 | Detached JWS with `b64=false` (RFC 7797): PyJWT Base64URL-decodes the payload segment before enforcing detached-payload rules, then discards it. A large payload segment forces CPU/memory work even with an invalid signature → unauthenticated DoS. |

**Impact:** Two of these (PYSEC-2026-176, PYSEC-2026-179) are auth-bypass / token-forgery class.
Superset uses JWTs for Guest Tokens (dashboard embedding) and async query auth, so this is the
most actionable runtime issue. The fix (2.13.0) is a same-major, low-risk bump.

### flask 2.3.3 → 3.1.3
| ID | Fix | Description |
|---|---|---|
| CVE-2026-27205 | 3.1.3 | When the `session` object is accessed (e.g. via the Python `in` operator), Flask fails to set the `Vary: Cookie` header in some cases. Behind a caching proxy that caches responses with cookies, this can leak a logged-in user's session-specific response to other users. Conditional — requires a caching proxy in front, no `Cache-Control: private`, and a specific session access pattern. |

**Impact:** Conditional / deployment-dependent. The fix is a **major version bump (2.x → 3.x)** with
breaking changes — needs testing across Superset + Flask-AppBuilder compatibility.

### paramiko 3.5.1
| ID | Fix | Description |
|---|---|---|
| CVE-2026-44405 | (none yet) | `rsakey.py` allows the SHA-1 algorithm (through 4.0.0 before commit a448945). |

**Impact:** No fixed release published yet — track upstream and bump when available.

## Dev / build-tooling only (not in production images) — lower urgency

### pip 25.1.1 → 26.1.2 (5 advisories)
| ID | Fix | Description |
|---|---|---|
| PYSEC-2026-196 | 26.1.2 | `console_scripts`/`gui_scripts` treated as paths without sanitizing resolved absolute path → entry points installed outside the install directory. |
| CVE-2025-8869 | 25.3 | Tar extraction may not check symlinks point inside the extraction dir when `tarfile` lacks PEP 706 (fallback path only; Python 3.12 implements PEP 706, so not triggered here). |
| CVE-2026-1703 | 26.0 | Maliciously crafted wheel can extract files outside the install dir (path traversal limited to prefixes of install dir). |
| CVE-2026-3219 | 26.1 | Concatenated tar+ZIP files handled as ZIP regardless of filename → confusing/incorrect install behavior. |
| CVE-2026-6357 | 26.1 | Self-update check ran after installing wheels, importing well-known module names — could import freshly installed modules. |

### starlette 0.49.1 → 1.0.1
| ID | Fix | Description |
|---|---|---|
| PYSEC-2026-161 | 1.0.1 | URL reconstructed from the `Host` header without validation; attacker can inject paths into the host part. Routing uses the real path, but the inconsistency can lead to auth bypass when auth depends on the reconstructed URL path. |

### jaraco-context 6.0.1 → 6.1.0
| ID | Fix | Description |
|---|---|---|
| CVE-2026-23949 | 6.1.0 | Zip-Slip path traversal in `jaraco.context.tarball()` (`strip_first_component` filter allows `../`). Also affects setuptools' vendored copy. |

### pytest 7.4.4 → 9.0.3
| ID | Fix | Description |
|---|---|---|
| CVE-2025-71176 | 9.0.3 | On UNIX, relies on `/tmp/pytest-of-{user}` directories → local DoS or possible privilege escalation. |

## Recommendations (priority order)

1. **pyjwt → ≥ 2.13.0** — fixes the auth-bypass / token-forgery class; same major version, low risk.
2. **flask → 3.1.3** — fixes the session/cache header leak, but is a major bump requiring
   compatibility testing (Flask-AppBuilder, extensions). Schedule rather than rush.
3. **starlette → 1.0.1**, **jaraco-context → 6.1.0**, **pytest → 9.0.3**, **pip → 26.1.2** —
   dev/build tooling; bump opportunistically (some are major bumps and need test runs).
4. **paramiko (CVE-2026-44405)** — no fix released yet; track upstream and bump when available.

> Reminder: `requirements/*.txt` are compiled lockfiles. The correct way to bump is to edit the
> corresponding `.in` files and re-run the compile step (the repo uses `uv`/`pip-compile`), not to
> hand-edit the pinned `.txt` files.
