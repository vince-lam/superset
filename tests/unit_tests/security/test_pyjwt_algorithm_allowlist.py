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
"""Regression tests for CVE-2026-48523 (PyJWT algorithm allow-list bypass).

PyJWT < 2.12.1 allowed a token signed with a disallowed algorithm to pass
verification when decoded with a ``PyJWK`` key, because the signature was
checked against the algorithm bound to the JWK rather than the header ``alg``.

These tests verify that the patched PyJWT correctly rejects such tokens.
"""

import base64
import json  # noqa: TID251

import jwt as pyjwt
import pytest
from jwt import PyJWK

SECRET_BYTES = b"a-secret-key-that-is-48-bytes-long-for-hs384!!"
JWK_DICT = {
    "kty": "oct",
    "k": base64.urlsafe_b64encode(SECRET_BYTES).decode().rstrip("="),
    "alg": "HS384",
}


def _tamper_header_alg(token: str, new_alg: str) -> str:
    """Replace the ``alg`` in a JWT header without re-signing."""
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
    header["alg"] = new_alg
    new_header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    )
    return f"{new_header_b64}.{payload_b64}.{sig_b64}"


def test_pyjwk_rejects_token_signed_with_disallowed_algorithm() -> None:
    """HS384 token must be rejected when only HS256 is allowed."""
    jwk_key = PyJWK(JWK_DICT)
    token = pyjwt.encode({"sub": "test"}, jwk_key.key, algorithm="HS384")

    with pytest.raises(pyjwt.exceptions.InvalidAlgorithmError):
        pyjwt.decode(token, jwk_key, algorithms=["HS256"])


def test_pyjwk_rejects_tampered_header_alg() -> None:
    """A token signed with HS384 but with its header rewritten to HS256 must be
    rejected — this is the exact attack vector of CVE-2026-48523."""
    jwk_key = PyJWK(JWK_DICT)
    token = pyjwt.encode({"sub": "test"}, jwk_key.key, algorithm="HS384")
    tampered = _tamper_header_alg(token, "HS256")

    with pytest.raises(
        (
            pyjwt.exceptions.InvalidAlgorithmError,
            pyjwt.exceptions.InvalidSignatureError,
        )
    ):
        pyjwt.decode(tampered, jwk_key, algorithms=["HS256"])
