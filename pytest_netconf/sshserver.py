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

import logging
import threading
import paramiko

from .settings import Settings


logger = logging.getLogger(__name__)


class SSHServer(paramiko.ServerInterface):
    """An SSH server."""

    def __init__(self, settings: Settings):
        """
        Initialise the SSH server.

        Args:
            settings (Settings): The SSH server settings.
        """
        self.event = threading.Event()
        self._settings = settings

    def check_channel_request(self, kind: str, _: int) -> int:
        """
        Check if a channel request is of type 'session'.

        Args:
            kind (str): The type of channel requested.

        Returns:
            int: The status of the channel request.
        """
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    def check_channel_pty_request(self, *_) -> bool:
        """
        Determine if a PTY can be provided.

        Returns:
            bool: True if the PTY has been allocated, else False.
        """
        return self._settings.allocate_pty

    def get_allowed_auths(self, username: str) -> str:
        return "password,publickey"

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Validate the username and password for authentication.

        Args:
            username (str): The username provided for authentication.
            password (str): The password provided for authentication.

        Returns:
            int: The status of the authentication request.
        """
        logger.debug("trying password auth for user: %s", self._settings.username)
        if not self._settings.username and not self._settings.password:
            logger.info("password auth successful using any username and password")
            return paramiko.AUTH_SUCCESSFUL
        if username == self._settings.username and password == self._settings.password:
            logger.info("password auth successful username and password match")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """
        Validate the username and SSH key for authentication.

        Args:
            username (str): The username provided for authentication.
            key (paramiko.PKey): The public key provided for authentication.

        Returns:
            int: The status of the authentication request.
        """
        logger.debug("trying publickey auth for user: %s", self._settings.username)
        if (
            username == self._settings.username
            and self._settings.authorized_key
            and f"{key.get_name()} {key.get_base64()}" == self._settings.authorized_key
        ):
            logger.info("publickey auth successful username and key match")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_subsystem_request(self, _: paramiko.Channel, name: str) -> bool:
        """
        Check if the requested subsystem is 'netconf'.

        Args:
            name (str): The name of the subsystem requested.

        Returns:
            bool: True if the subsystem is 'netconf', False otherwise.
        """
        if name == "netconf":
            self.event.set()
            return True
        return False  # pragma: no cover
