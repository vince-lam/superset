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

"""
Regression test for CVE-2026-48524 (PYSEC-2026-177).

PyJWT < 2.13.0 allowed ``PyJWKClient.get_signing_key()`` to issue an
unlimited number of HTTP requests to the JWKS endpoint for JWTs with
unknown ``kid`` values, enabling an attacker to trigger unbounded
outbound network traffic. The fix in 2.13.0 introduces rate limiting
for JWKS fetches.
"""

from packaging.version import Version


def test_pyjwt_version_has_jwks_ratelimit_fix() -> None:
    """PyJWT must be >=2.13.0 to include the CVE-2026-48524 fix."""
    import jwt

    assert Version(jwt.__version__) >= Version("2.13.0"), (
        f"pyjwt {jwt.__version__} is vulnerable to CVE-2026-48524; upgrade to >=2.13.0"
    )
