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
Regression test for CVE-2026-48522 (PYSEC-2026-175).

PyJWT < 2.13.0 allowed PyJWKClient to fetch JWKS URIs using any scheme
supported by urllib (file://, ftp://, data://), enabling SSRF against
the local filesystem or internal services when an attacker can influence
the JWKS URI.
"""

import pytest
from packaging.version import Version


def test_pyjwt_version_has_jwkclient_ssrf_fix() -> None:
    """PyJWT must be >=2.13.0 to include the CVE-2026-48522 fix."""
    import jwt

    assert Version(jwt.__version__) >= Version("2.13.0"), (
        f"pyjwt {jwt.__version__} is vulnerable to CVE-2026-48522; upgrade to >=2.13.0"
    )


@pytest.mark.parametrize(
    "uri",
    [
        "file:///etc/passwd",
        "ftp://evil.com/jwks.json",
        "data:application/json,{}",
    ],
    ids=["file", "ftp", "data"],
)
def test_pyjwkclient_rejects_non_http_schemes(uri: str) -> None:
    """PyJWKClient must reject non-HTTP(S) URI schemes.

    CVE-2026-48522: prior to the fix, PyJWKClient passed URIs directly
    to urllib.request.urlopen() which accepted file://, ftp://, and
    data:// schemes, allowing local file reads and broader SSRF.
    """
    from urllib.parse import urlparse

    from jwt import PyJWKClient, PyJWKClientError

    scheme = urlparse(uri).scheme
    with pytest.raises(PyJWKClientError) as exc_info:
        PyJWKClient(uri).fetch_data()
    assert scheme in str(exc_info.value).lower(), (
        f"Expected error to mention the rejected scheme '{scheme}', "
        f"got: {exc_info.value}"
    )
