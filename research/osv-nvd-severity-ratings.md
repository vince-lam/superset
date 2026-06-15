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

# OSV + NVD Severity Ratings — vince-lam/superset

**Date:** 2026-06-15
**Base:** `master` @ `2734bde504`
**Sources:** [OSV.dev API](https://api.osv.dev) (`/v1/querybatch` + `/v1/vulns/{id}`) and [NVD API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
**Scope:** all pinned packages in `requirements/base.txt` + `requirements/development.txt` (280 packages)
**Reproduce:** `python research/osv_nvd_scan.py` (raw output in `research/osv_nvd_results.json`)

## Method & rating scale

OSV was queried for every pinned `package==version`. For each returned advisory, the associated
CVE(s) were looked up in NVD for the authoritative **CVSS v3.1 base score** (falling back to CVSS
v4.0 when v3.1 is absent). Severity labels follow the standard CVSS qualitative bands:

| Label | CVSS base score |
|---|---|
| **Critical** | 9.0 – 10.0 |
| **High** | 7.0 – 8.9 |
| **Medium** | 4.0 – 6.9 |
| **Low** | 0.1 – 3.9 |

## Headline

OSV + NVD surface the **same 7 affected packages** that `pip-audit` reported — no *additional*
vulnerable packages were found (OSV draws from the same PyPI/GHSA advisory data). The new
information here is the **CVSS-scored severity** for each issue.

- **Critical:** 0
- **High:** 2
- **Medium:** 10
- **Low:** 3

> The two starlette advisories (`GHSA-86qp-5c8j-p5mr`, `PYSEC-2026-161`) are the same CVE
> (`CVE-2026-48710`), so there are **15 unique CVEs** below.

## High

| Severity | CVSS | Package | Version → Fix | CVE | OSV ID | Issue | Ships in prod? |
|---|---|---|---|---|---|---|---|
| **High** | **8.6** | jaraco-context | 6.0.1 → 6.1.0 | CVE-2026-23949 | GHSA-58pv-8j8x-9vj2 | Zip-Slip path traversal in `jaraco.context.tarball()` (also affects vendored setuptools copy). | No (build tooling) |
| **High** | **7.4** | pyjwt | 2.12.0 → 2.13.0 | CVE-2026-48526 | PYSEC-2026-179 | HMAC key-confusion: library doesn't validate JWK use in HMAC algo → issuer public key usable as HMAC secret (token forgery). | **Yes (runtime)** |

## Medium

| Severity | CVSS | Package | Version → Fix | CVE | OSV ID | Issue | Ships in prod? |
|---|---|---|---|---|---|---|---|
| **Medium** | 6.8 | pytest | 7.4.4 → 9.0.3 | CVE-2025-71176 | GHSA-6w46-j5rx-g56g | Predictable `/tmp/pytest-of-{user}` dir → local DoS / possible privesc. | No (test tooling) |
| **Medium** | 6.5 | starlette | 0.49.1 → 1.0.1 | CVE-2026-48710 | GHSA-86qp-5c8j-p5mr / PYSEC-2026-161 | Missing Host-header validation poisons `request.url.path` → path-based auth-check bypass. | No (dev dep) |
| **Medium** | 5.9 | pip | 25.1.1 → 25.3 | CVE-2025-8869 | GHSA-4xh5-x5gv-qwph | Fallback tar extraction doesn't verify symlinks stay in extraction dir (only when Python lacks PEP 706; 3.12 is safe). | No (build tooling) |
| **Medium** | 5.5 | pip | 25.1.1 → 26.1.2 | CVE-2026-8643 | PYSEC-2026-196 | `console_scripts`/`gui_scripts` treated as paths → entry points installed outside install dir. | No (build tooling) |
| **Medium** | 5.4 | pyjwt | 2.12.0 → 2.12.1 | CVE-2026-48523 | PYSEC-2026-176 | Verifier-side algorithm allow-list bypass with PyJWK key (token forged with disallowed algo accepted). | **Yes (runtime)** |
| **Medium** | 5.3 | pyjwt | 2.12.0 → 2.13.0 | CVE-2026-48525 | PYSEC-2026-178 | Detached JWS (`b64=false`) decodes payload before enforcing rules → unauthenticated CPU/memory DoS. | **Yes (runtime)** |
| **Medium** | 5.3 | pip | 25.1.1 → 26.1 | CVE-2026-6357 | GHSA-jp4c-xjxw-mgf9 | Self-update check ran after wheel install, importing freshly installed module names. | No (build tooling) |
| **Medium** | 4.6 | pip | 25.1.1 → 26.1 | CVE-2026-3219 | GHSA-58qw-9mgm-455v | Concatenated tar+ZIP handled as ZIP regardless of filename → confusing/incorrect install. | No (build tooling) |
| **Medium** | 4.3 | flask | 2.3.3 → 3.1.3 | CVE-2026-27205 | GHSA-68rp-wp8r-4726 | Missing `Vary: Cookie` on some session access → cached session leak behind a caching proxy. | **Yes (runtime)** |
| **Medium** | 4.2 | pyjwt | 2.12.0 → 2.13.0 | CVE-2026-48522 | PYSEC-2026-175 | `PyJWKClient` passes `uri` straight to `urlopen` (`file://`/FTP) → SSRF / local file read. | **Yes (runtime)** |

## Low

| Severity | CVSS | Package | Version → Fix | CVE | OSV ID | Issue | Ships in prod? |
|---|---|---|---|---|---|---|---|
| **Low** | 3.7 | pyjwt | 2.12.0 → 2.13.0 | CVE-2026-48524 | PYSEC-2026-177 | `get_signing_key()` makes an unrated fresh HTTP request per unknown `kid` → outbound request amplification. | **Yes (runtime)** |
| **Low** | 3.4 | paramiko | 3.5.1 → (none yet) | CVE-2026-44405 | GHSA-r374-rxx8-8654 | `rsakey.py` allows the SHA-1 algorithm. No fixed release published. | **Yes (runtime)** |
| **Low** | 2.0 | pip | 25.1.1 → 26.0 | CVE-2026-1703 | GHSA-6vgw-5pg2-w6jp | Crafted wheel can extract files outside install dir (limited to install-dir prefixes). | No (build tooling) |

## Notes / caveats

- **No Criticals (≥ 9.0).** The worst is `jaraco-context` at 8.6 (High) — but it's a build-time
  dependency, not shipped in production runtime.
- **Highest *runtime* (production-shipped) risk** is `pyjwt` CVE-2026-48526 (High, 7.4) plus the
  pyjwt MEDIUM cluster. Superset uses JWTs for Guest Tokens (dashboard embedding) and async query
  auth, so the pyjwt → 2.13.0 bump remains the single most valuable fix. Same major version, low risk.
- **CVSS version differences:** a few advisories carry CVSS v4.0 vectors in OSV that score lower
  than NVD's v3.1 (e.g. flask is 2.3 under CVSS v4.0 in OSV vs 4.3 under CVSS v3.1 in NVD). This
  table uses NVD's CVSS v3.1 base score as the primary number, falling back to v4.0 only when v3.1
  is unavailable (pip's CVE-2025-8869 / CVE-2026-3219 / CVE-2026-1703 / CVE-2026-6357).
- **CVE id mapping:** OSV assigns numeric CVEs (`CVE-2026-48522`…`48526`) to the pyjwt advisories
  that `pip-audit` listed only by their PYSEC ids (`PYSEC-2026-175`…`179`); both refer to the same
  issues. The PYSEC id is kept in the OSV ID column for cross-reference.
