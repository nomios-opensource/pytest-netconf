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

import re
import time
import socket
import logging
import threading
import typing as t
from enum import Enum
import xml.etree.ElementTree as ET
import paramiko

from .settings import Settings
from .exceptions import UnexpectedRequestError, RequestError
from .sshserver import SSHServer
from .constants import RPC_REPLY_OK, RPC_REPLY_ERROR


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetconfBaseVersion(Enum):
    """
    NETCONF protocol versions.
    """

    BASE_10 = "1.0"
    BASE_11 = "1.1"


class NetconfServer:
    """A NETCONF server implementation."""

    BASE_10_DELIMETER = b"]]>]]>"
    BASE_10_TEMPLATE = "{content}]]>]]>"
    BASE_11_DELIMETER = b"\n##\n"
    BASE_11_PATTERN = r"#(\d+)\n(.*)\n##$"
    BASE_11_TEMPLATE = "\n#{length}\n{content}\n##\n"
    SESSION_ID = 1

    def __init__(self):
        """
        Initialise the NETCONF server.
        """
        self.settings: Settings = Settings()
        self._base_version: NetconfBaseVersion = NetconfBaseVersion(
            self.settings.base_version
        )
        self._server_socket: t.Optional[socket.socket] = None
        self._client_socket: t.Optional[socket.socket] = None
        self.running: bool = False
        self._thread: t.Optional[threading.Thread] = None
        self._hello_sent: bool = False
        self.capabilities: t.List[str] = []

        self.responses: t.List[t.Tuple[str, str]] = []

    @property
    def host(self) -> str:
        """
        Get the host address for the server.

        Returns:
            str: The host address.
        """
        return self.settings.host

    @host.setter
    def host(self, value: str):
        """
        Set the host address for the server.

        Args:
            value (str): The new host address.
        """
        self.settings.host = value

    @property
    def port(self) -> int:
        """
        Get the port number for the server.

        Returns:
            int: The port number.
        """
        return self.settings.port

    @port.setter
    def port(self, value: int):
        """
        Set the port number for the server.

        Args:
            value (int): The new port number.
        """
        assert isinstance(value, int), "port value must be int"
        self.settings.port = value

    @property
    def username(self) -> str:
        """
        Get the username for authentication.

        Returns:
            str: The username.
        """
        return self.settings.username

    @username.setter
    def username(self, value: str):
        """
        Set the username for authentication.

        Args:
            value (str): The new username.
        """
        self.settings.username = value

    @property
    def password(self) -> t.Optional[str]:
        """
        Get the password for authentication.

        Returns:
            t.Optional[str]: The password, if set.
        """
        return self.settings.password

    @password.setter
    def password(self, value: t.Optional[str]):
        """
        Set the password for authentication.

        Args:
            value (t.Optional[str]): The new password.
        """
        self.settings.password = value

    @property
    def base_version(self) -> str:
        """
        Get the base NETCONF protocol version.

        Returns:
            str: The base version.
        """
        return self._base_version.value

    @base_version.setter
    def base_version(self, value: str):
        """
        Set the base NETCONF protocol version.

        Args:
            value (str): The new base version.

        Raises:
            ValueError: when version is invalid.
        """
        try:
            self._base_version = NetconfBaseVersion(value)
        except ValueError as e:
            raise ValueError(
                f"Invalid NETCONF base version {value}: must be '1.0' or '1.1'"
            ) from e

    @property
    def authorized_key(self) -> t.Optional[paramiko.PKey]:
        """
        Get the SSH authorized key authentication.

        Returns:
            t.Optional[paramiko.PKey]: The SSH authorized key, if set.
        """
        return self.settings.authorized_key

    @authorized_key.setter
    def authorized_key(self, value: t.Optional[paramiko.PKey]):
        """
        Set the SSH authorized key for authentication.

        Args:
            value (t.Optional[paramiko.PKey]): The new SSH authorized key string.
        """
        self.settings.authorized_key = value

    def _hello_response(self) -> str:
        """
        Return a hello response based on NETCONF version.

        Returns:
            str: The XML hello response.
        """
        response = f"""
            <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <capabilities>
                    <capability>urn:ietf:params:netconf:base:{self._base_version.value}</capability>"""

        # Add additional capabilities
        for capability in self.capabilities:
            response += f"""
                    <capability>{capability}</capability>"""

        response += f"""
                </capabilities>
                <session-id>{NetconfServer.SESSION_ID}</session-id>
            </hello>"""

        return response.strip("\n")

    def start(self) -> None:
        """
        Start the mock NETCONF server.

        Raises:
            OSError: If the server fails to bind to the specified port.
        """
        self.running = True
        self._hello_sent = False  # reset in case of restart
        self._bind_socket()
        self._thread = threading.Thread(target=self._run)
        self._thread.start()
        time.sleep(1)  # Give the server a moment to start

    def stop(self) -> None:
        """Stop the NETCONF server."""
        self.running = False
        if self._client_socket:
            self._client_socket.close()
        if self._server_socket:
            self._server_socket.close()
        if self._thread:
            self._thread.join()

    def _bind_socket(self) -> None:
        """
        Bind the server socket to the specified host and port.

        Raises:
            OSError: If the server fails to bind to the specified port.
        """
        for _ in range(5):  # Retry up to 5 times
            try:
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                )
                self._server_socket.bind((self.settings.host, self.settings.port))
                self._server_socket.listen(1)
                return
            except OSError as e:
                if e.errno == 48:  # Address already in use
                    logger.warning("port %d in use, retrying...", self.port)
                    time.sleep(1)
                else:
                    raise e
        raise OSError(
            f"could not bind to port {self.port}",
        )

    def _run(self) -> None:
        """Run the server to accept connections and process requests."""
        try:
            self._client_socket, _ = self._server_socket.accept()
            transport = paramiko.Transport(self._client_socket)
            transport.add_server_key(paramiko.RSAKey.generate(2048))
            server = SSHServer(self.settings)
            transport.start_server(server=server)
            channel = transport.accept(20)

            if channel is None:
                logger.error("channel was not created")
                return

            # Wait for the subsystem request
            server.event.wait(10)

            if server.event.is_set():
                self._handle_requests(channel)

        finally:
            if channel:
                try:
                    channel.close()
                except EOFError:  # pragma: no cover
                    pass
            transport.close()

    def _handle_requests(self, channel: paramiko.Channel) -> None:
        """
        Handle incoming requests on the channel.

        Args:
            channel (paramiko.Channel): The communication channel with the client.
        """
        buffer = bytearray()
        while self.running:
            try:
                # Send hello
                if not self._hello_sent:
                    channel.sendall(
                        NetconfServer.BASE_10_TEMPLATE.format(
                            content=self._hello_response()
                        ).encode()
                    )
                    self._hello_sent = True

                data = channel.recv(4096)
                if not data:
                    break
                buffer.extend(data)
                logger.debug("received data: %s", data.decode())
                while True:
                    processed = self._process_buffer(buffer, channel)
                    if not processed:
                        break
            except UnexpectedRequestError as e:
                logger.error("unexpected request error: %s", e)
            except Exception as e:
                msg = "failed to handle request: %s"
                logger.error(msg, e)
                logger.exception(e)
                raise RequestError(msg % e)

    def _process_buffer(self, buffer: bytearray, channel: paramiko.Channel) -> bool:
        """
        Process the buffered data to extract requests and send responses.

        Args:
            buffer (bytearray): The current buffer containing request data.
            channel (paramiko.Channel): The communication channel with the client.

        Returns:
            bool: True if a complete request was processed, else False.

        Raises:
            UnexpectedRequestError: when the request has no defined response.
        """
        # Handle client hello
        if b"hello" in buffer and b"capabilities" in buffer:
            logger.info("received client hello")
            del buffer[
                : buffer.index(NetconfServer.BASE_10_DELIMETER)
                + len(NetconfServer.BASE_10_DELIMETER)
            ]
            return True

        # Handle NETCONF v1.0
        elif (
            self._base_version is NetconfBaseVersion.BASE_10
            and NetconfServer.BASE_10_DELIMETER in buffer
        ):
            request_end_index = buffer.index(NetconfServer.BASE_10_DELIMETER)
            request = buffer[:request_end_index].decode()
            del buffer[: request_end_index + len(NetconfServer.BASE_10_DELIMETER)]
            logger.debug("processed request: %s", request)

        # Handle NETCONF v1.1
        elif (
            self._base_version is NetconfBaseVersion.BASE_11
            and NetconfServer.BASE_11_DELIMETER in buffer
        ):
            try:
                buffer_str = buffer.decode()
                length, request_content = self._extract_base11_content_and_length(
                    buffer_str
                )
                logger.debug(
                    "extracted content length=%d content: %s", length, request_content
                )
            except ValueError as e:
                logger.error("parse error: %s", e)
                return False  # Wait for more data if parsing fails

            request = request_content
            request_len = len(
                NetconfServer.BASE_11_TEMPLATE.format(length=length, content=request)
            )
            del buffer[:request_len]
        else:
            logger.debug("waiting for more data...")
            return False  # Wait for more data

        self._send_response(request, channel)
        logger.debug("buffer after processing: %s", buffer)
        return True

    def _extract_base11_content_and_length(self, buffer_str: str) -> t.Tuple[int, str]:
        """
        Extract the base 1.1 length value and content from string..

        Args:
            buffer_str (str): The input buffer string.

        Returns:
            t.Tuple[int, str]: The length value and the extracted content.

        Raises:
            ValueError: When length value cannot be parsed or is invalid.
        """

        if m := re.search(NetconfServer.BASE_11_PATTERN, buffer_str, flags=re.DOTALL):
            length = int(m.group(1))
            content = m.group(2)

            if len(content) != length:
                raise ValueError(
                    f"received invalid chunk size expected={len(content)} received={length}",
                )

            return length, content

        raise ValueError(f"Invalid content or chunk size format")

    def _extract_message_id(self, request: str) -> str:
        """
        Extract the message-id from an XML request.

        Args:
            request (str): The XML request string.

        Returns:
            str: The extracted message-id, or 'unknown' if parsing fails.
        """
        try:
            root = ET.fromstring(request)
            return root.get("message-id", "unknown")
        except ET.ParseError as e:
            logger.error("failed to parse XML request: %s", e)
            return "unknown"

    def _get_response(self, request: str) -> t.Optional[str]:
        """
        Get the appropriate response for a given request.

        Args:
            request (str): The request string to match against defined responses.

        Returns:
            t.Optional[str]: The matched response string, or None if no match is found.
        """

        for pattern, response in self.responses:
            formatted_pattern = pattern.format(
                message_id=self._extract_message_id(request),
                session_id=NetconfServer.SESSION_ID,
            )

            # Check for exact match or regex match
            if (formatted_pattern == request) or re.search(
                formatted_pattern, request, flags=re.DOTALL
            ):
                return re.sub(r"^\s+|\s+$", "", response)

        return None

    def _send_response(self, request: str, channel: paramiko.Channel) -> None:
        """
        Send a response to the client based on the request and protocol version.

        Args:
            request (str): The client's request.
            channel (paramiko.Channel): The communication channel with the client.

        Raises:
            UnexpectedRequestError: when the request has no defined response.
        """
        message_id = self._extract_message_id(request)
        response = self._get_response(request)

        def _fmt_response(_res: str) -> str:
            """Helper to format response depending on base version."""
            return (
                NetconfServer.BASE_10_TEMPLATE.format(content=_res.strip("\n"))
                if self._base_version is NetconfBaseVersion.BASE_10
                else NetconfServer.BASE_11_TEMPLATE.format(
                    length=len(_res.strip("\n")), content=_res.strip("\n")
                )
            )

        if "close-session" in request:
            channel.sendall(
                _fmt_response(RPC_REPLY_OK.format(message_id=message_id)).encode()
            ),

        elif response:
            response = response.format(message_id=message_id)
            channel.sendall(_fmt_response(response).encode())
        else:
            error_response = RPC_REPLY_ERROR.format(
                type="rpc",
                message_id=message_id,
                tag="operation-failed",
                message="pytest-netconf: requested rpc is unknown and has no response defined",
            )
            channel.sendall(_fmt_response(error_response).encode())
            raise UnexpectedRequestError(
                f"Received request which has no response defined: {request}"
            )

    def expect_request(
        self, request_pattern: t.Union[str, t.Pattern[str]]
    ) -> "NetconfServer.ResponseSetter":
        """
        Define expected requests and associated responses.

        Args:
            request_pattern (t.Union[str, Pattern[str]]): The expected request pattern.

        Returns:
            NetconfServer.ResponseSetter: A ResponseSetter to set the response for the request.
        """
        return self.ResponseSetter(self, request_pattern)

    class ResponseSetter:
        """Helper class to set responses for expected requests."""

        def __init__(
            self, server: "NetconfServer", request_pattern: t.Union[str, t.Pattern[str]]
        ):
            """
            Initialize the ResponseSetter.

            Args:
                server (NetconfServer): The server instance to set the response on.
                request_pattern (t.Union[str, Pattern[str]]): The expected request pattern.
            """
            self.server = server
            self._request_pattern = request_pattern

        def respond_with(self, response: str) -> "NetconfServer.ResponseSetter":
            """
            Set the response for the specified request pattern.

            Args:
                response (str): The response to associate with the request pattern.

            Returns:
                NetconfServer.ResponseSetter: The current instance for chaining.
            """
            self.server.responses.append((self._request_pattern, response))
            return self
