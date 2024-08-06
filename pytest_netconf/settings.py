"""
Copyright 2024 Nomios UK&I

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import os
import typing as t
from dataclasses import dataclass


@dataclass
class Settings:
    """
    pytest-netconf settings.
    """

    base_version: t.Literal["1.0", "1.1"] = os.getenv("PYTEST_NETCONF_VERSION", "1.1")
    host: str = os.getenv("PYTEST_NETCONF_HOST", "localhost")
    port: int = int(os.getenv("PYTEST_NETCONF_PORT", "8830"))
    username: t.Optional[str] = os.getenv("PYTEST_NETCONF_USERNAME")
    password: t.Optional[str] = os.getenv("PYTEST_NETCONF_PASSWORD")
    authorized_key: t.Optional[str] = os.getenv("PYTEST_NETCONF_AUTHORIZED_KEY")
    allocate_pty: bool = bool(
        (os.getenv("PYTEST_NETCONF_AUTHORIZED_KEY", "true")).lower() == "true"
    )
