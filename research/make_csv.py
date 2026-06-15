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
import csv
import json
from pathlib import Path

REPO = Path("/home/ubuntu/superset")

RUNTIME_PKGS = {"flask", "paramiko", "pyjwt"}  # ship in production runtime
TOOLING_PKGS = {"pip", "pytest", "jaraco-context", "starlette"}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "": 5}


def main():
    rows = json.loads((REPO / "research" / "osv_nvd_results.json").read_text())
    out = []
    for r in rows:
        pkg = r["package"]
        ships = "runtime" if pkg in RUNTIME_PKGS else "tooling"
        out.append({
            "package": pkg,
            "installed_version": r["version"],
            "fix_versions": ";".join(r["fix_versions"]) if r["fix_versions"] else "none",
            "cve": ";".join(r["cves"]) if r["cves"] else "",
            "osv_id": r["osv_id"],
            "cvss_score": r["nvd_best_score"] if r["nvd_best_score"] is not None else "",
            "severity": (r["nvd_best_severity"] or "").upper(),
            "ships_in_production": ships,
            "summary": r["summary"],
        })

    out.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 5),
                            -(x["cvss_score"] if isinstance(x["cvss_score"], (int, float)) else 0)))

    fields = ["package", "installed_version", "fix_versions", "cve", "osv_id",
              "cvss_score", "severity", "ships_in_production", "summary"]
    out_path = REPO / "research" / "flagged_packages.csv"
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(out)
    print(f"Wrote {len(out)} rows to {out_path}")


if __name__ == "__main__":
    main()
