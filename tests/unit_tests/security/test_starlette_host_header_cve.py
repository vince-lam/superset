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
Regression test for CVE-2026-48710 (GHSA-86qp-5c8j-p5mr).

Starlette <1.0.1 reconstructed request.url.path from the Host header
without validation, allowing an attacker to inject paths via the Host
header and bypass authentication checks that rely on the reconstructed
URL path.
"""

from packaging.version import Version
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient


def test_starlette_version_has_host_header_fix() -> None:
    """Starlette must be >=1.0.1 to include the CVE-2026-48710 fix."""
    import starlette

    assert Version(starlette.__version__) >= Version("1.0.1"), (
        f"starlette {starlette.__version__} is vulnerable to CVE-2026-48710; "
        "upgrade to >=1.0.1"
    )


def test_host_header_does_not_poison_request_url_path() -> None:
    """Injected paths in the Host header must not alter request.url.path.

    CVE-2026-48710: prior to the fix, a crafted Host header like
    ``evil.com/admin`` would cause ``request.url.path`` to include
    ``/admin`` even though the actual request path was ``/public``.
    """

    async def echo_path(request: Request) -> JSONResponse:
        return JSONResponse({"url_path": request.url.path})

    app = Starlette(routes=[Route("/public", echo_path)])
    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/public", headers={"Host": "evil.com/admin"})

    if response.status_code == 400:
        return

    assert response.status_code == 200
    data = response.json()
    assert data["url_path"] == "/public", (
        f"Host header injection poisoned request.url.path: {data['url_path']}"
    )
