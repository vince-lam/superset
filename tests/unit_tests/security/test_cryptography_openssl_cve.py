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
Regression test for GHSA-537c-gmf6-5ccf.

cryptography wheels prior to 48.0.1 bundle a statically linked OpenSSL
that is vulnerable to the issues described in
https://openssl-library.org/news/secadv/20260609.txt.
"""

from packaging.version import Version


def test_cryptography_version_has_openssl_fix() -> None:
    """cryptography must be >=48.0.1 to include the GHSA-537c-gmf6-5ccf fix."""
    import cryptography

    assert Version(cryptography.__version__) >= Version("48.0.1"), (
        f"cryptography {cryptography.__version__} is vulnerable to "
        "GHSA-537c-gmf6-5ccf; upgrade to >=48.0.1"
    )
