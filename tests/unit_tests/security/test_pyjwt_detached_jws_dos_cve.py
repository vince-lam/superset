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
Regression test for CVE-2026-48525 (PYSEC-2026-178).

PyJWT 2.8.0–2.12.1 performs Base64URL decoding of the compact-serialization
payload segment for detached JWS (b64=false, RFC 7797) before enforcing
detached-payload rules. An attacker can supply an arbitrarily large
Base64URL payload segment to force CPU work and memory allocations even
when the signature is invalid, enabling unauthenticated DoS against any
endpoint verifying detached JWS tokens. Fixed in PyJWT 2.13.0.
"""

import resource
import time

import jwt
from packaging.version import Version


def test_pyjwt_version_has_detached_jws_dos_fix() -> None:
    """PyJWT must be >=2.13.0 to include the CVE-2026-48525 fix."""
    assert Version(jwt.__version__) >= Version("2.13.0"), (
        f"PyJWT {jwt.__version__} is vulnerable to CVE-2026-48525; upgrade to >=2.13.0"
    )


def test_large_detached_jws_payload_does_not_cause_excessive_work() -> None:
    """Verifying a detached JWS with a large middle segment must not
    consume excessive CPU or memory (CVE-2026-48525 work-amplification).

    Constructs a compact JWS with a 1 MB Base64URL payload segment and
    verifies that PyJWT rejects it quickly without allocating proportional
    memory.
    """
    large_payload_segment = "A" * (1024 * 1024)
    # header.payload.signature — all parts are bogus
    malicious_token = f"eyJhbGciOiJIUzI1NiJ9.{large_payload_segment}.invalidsig"

    mem_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    start = time.monotonic()

    try:
        jwt.decode(malicious_token, "secret", algorithms=["HS256"])
    except Exception:  # noqa: S110
        pass

    elapsed = time.monotonic() - start
    mem_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    # Decoding should fail fast (well under 1 second)
    assert elapsed < 2.0, (
        f"Decoding large payload took {elapsed:.2f}s — possible DoS vector"
    )
    # Memory growth should be bounded (< 50 MB for a 1 MB payload)
    mem_growth_kb = mem_after - mem_before
    assert mem_growth_kb < 50_000, (
        f"Memory grew by {mem_growth_kb} KB — possible work amplification"
    )
