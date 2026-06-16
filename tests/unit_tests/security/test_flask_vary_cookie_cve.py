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
Regression test for CVE-2026-27205.

Flask <3.1.1 did not set the ``Vary: Cookie`` response header when the
session was accessed via the Python ``in`` operator (e.g. ``"key" in
session``).  Without ``Vary: Cookie``, an intermediate cache might serve
the authenticated response to unauthenticated users.

Advisory: https://github.com/advisories/CVE-2026-27205
"""

import flask
from packaging.version import Version


def test_flask_version_has_vary_cookie_fix() -> None:
    """Flask must be >=3.1.1 to include the CVE-2026-27205 fix."""
    assert Version(flask.__version__) >= Version("3.1.1"), (
        f"flask {flask.__version__} is vulnerable to CVE-2026-27205; upgrade to >=3.1.1"
    )


def test_session_in_operator_sets_vary_cookie() -> None:
    """Accessing session via ``in`` must add ``Vary: Cookie`` header.

    CVE-2026-27205: the ``__contains__`` (``in``) path on the session
    proxy did not trigger the ``Vary: Cookie`` header, allowing caches
    to serve session-dependent responses to the wrong user.
    """
    app = flask.Flask(__name__)
    app.secret_key = "test-secret"  # noqa: S105

    @app.route("/check")
    def check() -> str:
        # Access session with the ``in`` operator — the patched path.
        _ = "user" in flask.session
        return "ok"

    client = app.test_client()
    response = client.get("/check")

    assert response.status_code == 200
    vary = response.headers.get("Vary", "")
    assert "Cookie" in vary, (
        f"Expected 'Vary: Cookie' header when session is accessed via "
        f"``in`` operator, got Vary={vary!r}"
    )
