# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import json
import re
import time
import urllib.request
import urllib.error
from pathlib import Path

REPO = Path("/home/ubuntu/superset")
REQ_FILES = [
    "requirements/base.txt",
    "requirements/development.txt",
]

pkg_re = re.compile(r"^([A-Za-z0-9_.\-]+)==([A-Za-z0-9_.\-+!]+)")


def parse_requirements(path):
    pkgs = {}
    for line in (REPO / path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        m = pkg_re.match(line)
        if m:
            pkgs[m.group(1).lower()] = m.group(2)
    return pkgs


def http_post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def osv_querybatch(pkgs):
    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": ver}
        for name, ver in pkgs.items()
    ]
    res = http_post("https://api.osv.dev/v1/querybatch", {"queries": queries})
    out = {}
    names = list(pkgs.keys())
    for name, result in zip(names, res.get("results", [])):
        vulns = result.get("vulns", [])
        if vulns:
            out[name] = [v["id"] for v in vulns]
    return out


def osv_vuln(vuln_id):
    return http_get(f"https://api.osv.dev/v1/vulns/{vuln_id}")


def cvss_to_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def parse_cvss_vector_score(vector):
    # Use cvss library if available else None; we rely on provided base scores instead.
    return None


def extract_osv_severity(vuln):
    # OSV 'severity' field holds CVSS vectors; database_specific sometimes has score.
    sev = vuln.get("severity", [])
    vectors = {}
    for s in sev:
        vectors[s.get("type")] = s.get("score")
    return vectors


def aliases(vuln):
    return vuln.get("aliases", [])


def get_cve_ids(vuln):
    ids = []
    if vuln.get("id", "").startswith("CVE-"):
        ids.append(vuln["id"])
    for a in aliases(vuln):
        if a.startswith("CVE-"):
            ids.append(a)
    return list(dict.fromkeys(ids))


def main():
    pkgs = {}
    for f in REQ_FILES:
        pkgs.update(parse_requirements(f))
    print(f"Parsed {len(pkgs)} pinned packages")

    osv_hits = osv_querybatch(pkgs)
    print(f"OSV: {sum(len(v) for v in osv_hits.values())} vuln ids across {len(osv_hits)} packages")

    findings = []
    seen = set()
    for name, ids in osv_hits.items():
        for vid in ids:
            if vid in seen:
                continue
            seen.add(vid)
            try:
                v = osv_vuln(vid)
            except Exception as e:
                print(f"  ! failed osv vuln {vid}: {e}")
                continue
            findings.append((name, pkgs[name], v))
            time.sleep(0.1)

    # NVD lookups for CVSS
    nvd_cache = {}

    def nvd_lookup(cve):
        if cve in nvd_cache:
            return nvd_cache[cve]
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        for attempt in range(4):
            try:
                data = http_get(url, headers={"User-Agent": "superset-research-script"})
                nvd_cache[cve] = data
                time.sleep(6.5)  # respect 5 req / 30s without API key
                return data
            except urllib.error.HTTPError as e:
                if e.code in (403, 503, 429):
                    time.sleep(10)
                    continue
                nvd_cache[cve] = None
                return None
            except Exception:
                time.sleep(5)
        nvd_cache[cve] = None
        return None

    def nvd_score(cve):
        data = nvd_lookup(cve)
        if not data:
            return None, None, None
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None, None, None
        metrics = vulns[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cd = m.get("cvssData", {})
                score = cd.get("baseScore")
                sev = cd.get("baseSeverity") or m.get("baseSeverity")
                vec = cd.get("vectorString")
                return score, sev, vec
        return None, None, None

    rows = []
    for name, ver, v in findings:
        vid = v.get("id")
        cves = get_cve_ids(v)
        osv_sev = extract_osv_severity(v)
        nvd_results = {}
        best_score = None
        best_sev = None
        for cve in cves:
            score, sev, vec = nvd_score(cve)
            nvd_results[cve] = {"score": score, "severity": sev, "vector": vec}
            if score is not None and (best_score is None or score > best_score):
                best_score = score
                best_sev = sev
        # fall back to OSV CVSS vector severity label if NVD missing
        summary = v.get("summary", "")
        fix_versions = []
        for aff in v.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fix_versions.append(ev["fixed"])
        rows.append({
            "package": name,
            "version": ver,
            "osv_id": vid,
            "cves": cves,
            "summary": summary,
            "osv_severity_vectors": osv_sev,
            "nvd": nvd_results,
            "nvd_best_score": best_score,
            "nvd_best_severity": best_sev,
            "fix_versions": sorted(set(fix_versions)),
        })

    out_path = REPO / "research" / "osv_nvd_results.json"
    out_path.write_text(json.dumps(rows, indent=2))
    print(f"Wrote {len(rows)} findings to {out_path}")


if __name__ == "__main__":
    main()
