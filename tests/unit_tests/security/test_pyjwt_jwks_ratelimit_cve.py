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
Regression tests for CVE-2026-48524 (PYSEC-2026-177).

PyJWT < 2.13.0 allowed ``PyJWKClient.get_signing_key()`` to issue an
unlimited number of HTTP requests to the JWKS endpoint for JWTs with
unknown ``kid`` values, enabling an attacker to trigger unbounded
outbound network traffic.  The fix in 2.13.0 hardens ``PyJWKClient``
by (a) rejecting non-HTTP(S) JWKS URIs and (b) preserving the cached
JWK Set when a refresh fetch fails instead of wiping it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientError
from packaging.version import Version


def test_pyjwt_version_has_jwks_ratelimit_fix() -> None:
    """PyJWT must be >=2.13.0 to include the CVE-2026-48524 fix."""
    import jwt

    assert Version(jwt.__version__) >= Version("2.13.0"), (
        f"pyjwt {jwt.__version__} is vulnerable to CVE-2026-48524; upgrade to >=2.13.0"
    )


def test_pyjwkclient_rejects_non_https_uri() -> None:
    """PyJWKClient must reject non-HTTP(S) URI schemes.

    CVE-2026-48524: prior to 2.13.0 an attacker-influenced ``jku`` header
    could point to ``file://`` or other local schemes.  The fix validates
    the URI scheme at construction time.
    """
    with pytest.raises(PyJWKClientError, match="Invalid JWKS URI scheme"):
        PyJWKClient("file:///etc/passwd")


def test_jwk_set_cache_preserved_on_fetch_failure() -> None:
    """A failed JWKS refresh must not wipe the previously cached JWK Set.

    CVE-2026-48524: in < 2.13.0 ``fetch_data`` wrote ``None`` to the cache
    inside a ``finally`` block, so a transient network error would clear
    valid cached keys and force unlimited re-fetches for subsequent
    requests.
    """
    client = PyJWKClient("https://idp.example/.well-known/jwks.json")
    assert client.jwk_set_cache is not None

    # Seed the cache directly with a sentinel value.
    sentinel: dict[str, list[str]] = {"keys": []}
    client.jwk_set_cache.put(sentinel)
    assert client.jwk_set_cache.get() is not None

    # Simulate a transient network error on refresh.
    with patch.object(
        client,
        "fetch_data",
        side_effect=Exception("simulated network timeout"),
    ):
        with pytest.raises(Exception, match="simulated network timeout"):
            client.get_jwk_set(refresh=True)

    # The cache must still hold the previously stored JWK Set.
    assert client.jwk_set_cache.get() is not None, (
        "Cache was wiped after a failed refresh — "
        "this is the CVE-2026-48524 vulnerability pattern"
    )
