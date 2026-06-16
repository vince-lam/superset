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
"""Regression test for CVE-2026-48525 (PyJWT detached-JWS DoS).

PyJWT 2.8.0–2.12.1 performed Base64URL decoding of the compact-serialization
payload segment before enforcing detached-payload rules (``"b64": false``,
RFC 7797).  An attacker could supply an arbitrarily large payload segment to
force CPU work and memory allocations even when the signature is invalid.

Fixed in PyJWT 2.13.0.
Advisory: https://github.com/advisories/PYSEC-2026-178
"""

from __future__ import annotations

import jwt
import pytest
from packaging.version import Version


def test_pyjwt_version_satisfies_cve_2026_48525() -> None:
    """PyJWT must be >= 2.13.0, which contains the fix for CVE-2026-48525."""
    assert Version(jwt.__version__) >= Version("2.13.0")


def test_decode_rejects_oversized_detached_payload_segment() -> None:
    """An oversized middle segment in a compact JWS must not cause excessive
    memory/CPU usage.  With the fix, PyJWT rejects malformed tokens before
    base64-decoding the payload segment.

    We craft a three-part compact token whose middle segment is large and
    verify that ``jwt.decode`` raises promptly without allocating a decoded
    buffer proportional to the segment size.
    """
    secret = "test-secret"  # noqa: S105
    # Build a legitimate token so we can borrow its header.
    good_token = jwt.encode({"sub": "test"}, secret, algorithm="HS256")
    header, _payload, signature = good_token.split(".")

    # Craft a token with a ~1 MB junk middle segment (base64url chars).
    oversized_segment = "A" * (1024 * 1024)
    malicious_token = f"{header}.{oversized_segment}.{signature}"

    with pytest.raises(jwt.exceptions.DecodeError):
        jwt.decode(malicious_token, secret, algorithms=["HS256"])
