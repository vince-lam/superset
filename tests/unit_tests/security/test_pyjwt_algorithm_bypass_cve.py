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
Regression test for CVE-2026-48523 (PYSEC-2026-176).

PyJWT 2.9.0–2.12.0 had a verifier-side algorithm allow-list bypass when
jwt.decode() is called with a PyJWK key. The token header ``alg`` is checked
against the caller-supplied ``algorithms`` allow-list, but signature
verification used the algorithm bound to the PyJWK object instead of the
header algorithm. An attacker controlling a JWK private key could sign
with a disallowed algorithm, advertise an allowed algorithm in the JWT
header, and still be accepted.

Fixed in PyJWT 2.12.1+.
"""

import jwt
from packaging.version import Version

from superset.utils import json


def test_pyjwt_version_has_algorithm_bypass_fix() -> None:
    """PyJWT must be >=2.12.1 to include the CVE-2026-48523 fix."""
    assert Version(jwt.__version__) >= Version("2.12.1"), (
        f"pyjwt {jwt.__version__} is vulnerable to CVE-2026-48523; upgrade to >=2.12.1"
    )


def test_pyjwt_rejects_algorithm_mismatch_with_jwk() -> None:
    """jwt.decode() must reject tokens whose header alg differs from the JWK alg.

    CVE-2026-48523: prior to the fix, a token signed with HS384 but
    carrying ``"alg": "HS256"`` in its header would pass validation when
    decoded with a PyJWK whose algorithm was HS384, because the allow-list
    check only looked at the header while verification used the JWK alg.
    """
    secret = "test-jwt-key"  # noqa: S105

    # Build a JWK for HS384
    jwk_dict = {
        "kty": "oct",
        "k": jwt.utils.base64url_encode(secret.encode()).decode(),
        "alg": "HS384",
    }
    signing_key = jwt.PyJWK(jwk_dict)

    # Sign a token with HS384 (the JWK's actual algorithm)
    token = jwt.encode({"sub": "attacker"}, signing_key.key, algorithm="HS384")

    # Tamper the header to claim HS256 (the "allowed" algorithm)
    header_b64, payload_b64, sig_b64 = token.split(".")
    header_json = jwt.utils.base64url_decode(header_b64)
    header = json.loads(header_json)
    header["alg"] = "HS256"
    tampered_header_b64 = jwt.utils.base64url_encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).decode()
    tampered_token = f"{tampered_header_b64}.{payload_b64}.{sig_b64}"

    # Decode allowing only HS256 — the tampered header says HS256 but the
    # signature is actually HS384.  A patched PyJWT must reject this.
    try:
        jwt.decode(tampered_token, signing_key, algorithms=["HS256"])
    except (jwt.InvalidAlgorithmError, jwt.InvalidSignatureError, jwt.DecodeError):
        return  # Correctly rejected

    raise AssertionError(
        "jwt.decode() accepted a token whose header alg (HS256) differs "
        "from the JWK signing alg (HS384) — CVE-2026-48523 is exploitable"
    )
