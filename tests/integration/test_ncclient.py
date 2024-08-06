import pytest
import paramiko
from pytest_netconf import NetconfServer

from ncclient import manager
from ncclient.transport.errors import (
    AuthenticationError,
    TransportError,
)
from ncclient.operations.rpc import RPCError


@pytest.mark.parametrize("base_version", ["1.0", "1.1"])
def test_when_full_request_and_response_is_defined_then_response_is_returned(
    base_version,
    netconf_server: NetconfServer,
):
    # GIVEN server base version
    netconf_server.base_version = base_version

    # GIVEN server request and response are defined
    netconf_server.expect_request(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<nc:rpc xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">'
        "<nc:get-config><nc:source><nc:running/></nc:source></nc:get-config>"
        "</nc:rpc>"
    ).respond_with(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply message-id="{message_id}"
          xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <data>
                <interfaces>
                    <interface>
                        <name>eth0</name>
                    </interface>
                </interfaces>
            </data>
        </rpc-reply>"""
    )

    # WHEN fetching rpc response from server
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        response = m.get_config(source="running").data_xml

    # THEN expect response
    assert (
        """
                <interfaces>
                    <interface>
                        <name>eth0</name>
                    </interface>
                </interfaces>
        """
        in response
    )


@pytest.mark.parametrize("base_version", ["1.0", "1.1"])
def test_when_regex_request_and_response_is_defined_then_response_is_returned(
    base_version,
    netconf_server: NetconfServer,
):
    # GIVEN server base version
    netconf_server.base_version = base_version

    # GIVEN server request and response are defined
    netconf_server.expect_request(
        ".*<nc:get-config><nc:source><nc:running/></nc:source></nc:get-config>.*"
    ).respond_with(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply message-id="{message_id}"
          xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <data>
                <interfaces>
                    <interface>
                        <name>eth0</name>
                    </interface>
                </interfaces>
            </data>
        </rpc-reply>"""
    )

    # WHEN fetching rpc response from server
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        response = m.get_config(source="running").data_xml

    # THEN expect response
    assert (
        """
                <interfaces>
                    <interface>
                        <name>eth0</name>
                    </interface>
                </interfaces>
        """
        in response
    )


def test_when_unexpected_request_received_then_error_response_is_returned(
    netconf_server: NetconfServer,
):
    # GIVEN no server request and response are defined
    netconf_server

    # WHEN fetching rpc response from server
    with pytest.raises(RPCError) as error:
        with manager.connect(
            host="localhost",
            port=8830,
            username="admin",
            password="admin",
            hostkey_verify=False,
            manager_params={"timeout": 10},
        ) as m:
            m.foo(source="running")

    # THEN
    assert (
        str(error.value)
        == "pytest-netconf: requested rpc is unknown and has no response defined"
    )


def test_when_server_stops_then_client_error_is_raised(
    netconf_server: NetconfServer,
):
    # GIVEN netconf connection
    with pytest.raises(TransportError) as error:
        with manager.connect(
            host="localhost",
            port=8830,
            username="admin",
            password="admin",
            hostkey_verify=False,
        ) as m:
            pass
            # WHEN server stops
            netconf_server.stop()

    # THEN expect error
    assert str(error.value) == "Not connected to NETCONF server"


@pytest.mark.parametrize("base_version", ["1.0", "1.1"])
def test_when_defining_custom_capabilities_then_server_returns_them(
    base_version,
    netconf_server: NetconfServer,
):
    # GIVEN server version
    netconf_server.base_version = base_version

    # GIVEN extra capabilities
    netconf_server.capabilities.append("urn:ietf:params:netconf:capability:foo:1.1")
    netconf_server.capabilities.append("urn:ietf:params:netconf:capability:bar:1.1")

    # WHEN receiving server capabilities connection to server
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        server_capabilities = m.server_capabilities

    # THEN expect to see capabilities
    assert f"urn:ietf:params:netconf:base:{base_version}" in server_capabilities
    assert "urn:ietf:params:netconf:capability:foo:1.1" in server_capabilities
    assert "urn:ietf:params:netconf:capability:bar:1.1" in server_capabilities


def test_when_connecting_using_no_username_or_password_then_authentication_passes(
    netconf_server: NetconfServer,
):
    # GIVEN no username and password have been defined
    netconf_server.username = None
    netconf_server.password = None

    # WHEN connecting using random credentials
    with manager.connect(
        host="localhost",
        port=8830,
        username="foo",
        password="bar",
        hostkey_verify=False,
    ) as m:
        # THEN expect to be connected
        assert m.connected


def test_when_connecting_using_username_and_password_then_authentication_passes(
    netconf_server: NetconfServer,
):
    # GIVEN username and password have been defined
    netconf_server.username = "admin"
    netconf_server.password = "password"

    # WHEN connecting using correct credentials
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="password",
        hostkey_verify=False,
    ) as m:
        # THEN expect to be connected
        assert m.connected


def test_when_connecting_using_username_and_password_then_authentication_fails(
    netconf_server: NetconfServer,
):
    # GIVEN username and password have been defined
    netconf_server.username = "admin"
    netconf_server.password = "password"

    # WHEN connecting using wrong credentials
    with pytest.raises(AuthenticationError) as error:
        with manager.connect(
            host="localhost",
            port=8830,
            username="foo",
            password="bar",
            hostkey_verify=False,
        ):
            ...

    # THEN expect error
    assert error


def test_when_connecting_using_username_and_rsa_key_then_authentication_passes(
    netconf_server, tmp_path
):
    # GIVEN generated key
    key_filepath = (tmp_path / "key").as_posix()
    key = paramiko.RSAKey.generate(bits=2048)
    key.write_private_key_file(key_filepath)

    # GIVEN SSH username and key have been defined
    netconf_server.username = "admin"
    netconf_server.authorized_key = f"{key.get_name()} {key.get_base64()}"

    # WHEN connecting using key credentials
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        key_filename=key_filepath,
        hostkey_verify=False,
    ) as m:
        # THEN expect to be connected
        assert m.connected
