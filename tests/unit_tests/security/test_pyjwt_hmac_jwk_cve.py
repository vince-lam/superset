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
Regression test for CVE-2026-48526 (PYSEC-2026-179).

PyJWT <2.13.0 did not validate the use of JSON Web Keys (JWK) when an
HMAC algorithm was specified.  An attacker who knows the issuer's RSA
public key could craft an HMAC-signed token using that public key as
the HMAC secret, and PyJWT would accept it when both asymmetric and
HMAC algorithms were allowed.
"""

import jwt
from packaging.version import Version

from superset.utils import json


def test_pyjwt_version_has_hmac_jwk_fix() -> None:
    """PyJWT must be >=2.13.0 to include the CVE-2026-48526 fix."""
    assert Version(jwt.__version__) >= Version("2.13.0"), (
        f"PyJWT {jwt.__version__} is vulnerable to CVE-2026-48526; upgrade to >=2.13.0"
    )


def test_hmac_decode_rejects_jwk_public_key() -> None:
    """HMAC decode must reject a JWK dict passed as the key.

    CVE-2026-48526: prior to the fix, ``jwt.decode`` with
    ``algorithms=["HS256"]`` would accept a JWK-formatted RSA public
    key as the HMAC secret, enabling an algorithm-confusion attack.
    PyJWT >=2.13.0 validates that JWK keys are not used with HMAC.
    """
    rsa_n = (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4"
        "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiF"
        "V4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C"
        "f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c"
        "7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhA"
        "I4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF"
        "44-csFCur-kEgU8awapJzKnqDKgw"
    )
    jwk_public_key: dict[str, str] = {
        "kty": "RSA",
        "n": rsa_n,
        "e": "AQAB",
    }
    jwk_json = json.dumps(jwk_public_key)

    payload = {"sub": "attacker", "admin": True}
    forged_token = jwt.encode(payload, jwk_json, algorithm="HS256")

    # Decoding with the same JWK JSON as secret must fail — accepting
    # it would mean an attacker with the public key can forge tokens.
    try:
        jwt.decode(forged_token, jwk_json, algorithms=["HS256"])
    except (jwt.exceptions.InvalidKeyError, jwt.exceptions.DecodeError):
        return  # Expected: PyJWT >=2.13.0 rejects this

    raise AssertionError(
        "PyJWT accepted an HMAC token verified with a JWK public key; "
        "this indicates CVE-2026-48526 is not patched"
    )
