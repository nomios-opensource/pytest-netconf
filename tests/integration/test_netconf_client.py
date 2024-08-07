import paramiko.ssh_exception
import pytest
import paramiko
from pytest_netconf import NetconfServer

from netconf_client.connect import connect_ssh
from netconf_client.ncclient import Manager
from netconf_client.error import RpcError


@pytest.mark.parametrize("base_version", ["1.0", "1.1"])
def test_when_full_request_and_response_is_defined_then_response_is_returned(
    base_version,
    netconf_server: NetconfServer,
):
    # GIVEN server base version
    netconf_server.base_version = base_version

    # GIVEN server request and response are defined
    netconf_server.expect_request(
        '<rpc message-id="{message_id}" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
        '<get-config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"><source><running/></source></get-config>'
        "</rpc>"
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
    with connect_ssh(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
    ) as session:
        manager = Manager(session=session)
        response = manager.get_config(source="running").data_xml

    # THEN expect response
    assert (
        """
                <interfaces>
                    <interface>
                        <name>eth0</name>
                    </interface>
                </interfaces>
        """.strip(
            "\n"
        )
        in response.decode()
    )


@pytest.mark.parametrize("base_version", ["1.0", "1.1"])
def test_when_regex_request_and_response_is_defined_then_response_is_returned(
    base_version,
    netconf_server: NetconfServer,
):
    # GIVEN server base version
    netconf_server.base_version = base_version

    # GIVEN server request and response are defined
    netconf_server.expect_request("get-config").respond_with(
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
    with connect_ssh(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
    ) as session:
        manager = Manager(session=session)
        response = manager.get_config(source="running").data_xml

    # THEN expect response
    # THEN expect response
    assert (
        """
                <interfaces>
                    <interface>
                        <name>eth0</name>
                    </interface>
                </interfaces>
        """.strip(
            "\n"
        )
        in response.decode()
    )


def test_when_unexpected_request_received_then_error_response_is_returned(
    netconf_server: NetconfServer,
):
    # GIVEN no server request and response are defined
    netconf_server

    # WHEN fetching rpc response from server
    with pytest.raises(RpcError) as error:
        with connect_ssh(
            host="localhost",
            port=8830,
            username="admin",
            password="admin",
        ) as session:
            Manager(session=session).get_config(source="running")

    # THEN expect error response
    assert (
        str(error.value)
        == "pytest-netconf: requested rpc is unknown and has no response defined"
    )


def test_when_server_stops_then_client_error_is_raised(
    netconf_server: NetconfServer,
):
    # GIVEN netconf connection
    with pytest.raises(OSError) as error:
        with connect_ssh(
            host="localhost",
            port=8830,
            username="admin",
            password="admin",
            general_timeout=5,
        ) as session:
            manager = Manager(session=session)

            # WHEN server stops
            netconf_server.stop()
            manager.get_config()  # and a request is attempted
            session.session_id # needed to probe session

    # THEN expect error
    assert str(error.value) == "Socket is closed"


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
    with connect_ssh(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
    ) as session:
        server_capabilities = session.server_capabilities

    # THEN expect to see capabilities
    assert f"urn:ietf:params:netconf:base:{base_version}" in server_capabilities
    assert "urn:ietf:params:netconf:capability:foo:1.1" in server_capabilities
    assert "urn:ietf:params:netconf:capability:bar:1.1" in server_capabilities


def test_when_connecting_using_no_username_or_password_then_authentication_passes(
    netconf_server: NetconfServer,
):
    # GIVEN no username and password have been defined
    netconf_server
    netconf_server.username = None
    netconf_server.password = None

    # WHEN connecting using random credentials
    with connect_ssh(
        host="localhost",
        port=8830,
        username="foo",
        password="bar",
    ) as session:
        # THEN expect to be connected
        assert session.session_id


def test_when_connecting_using_username_and_password_then_authentication_passes(
    netconf_server: NetconfServer,
):
    # GIVEN username and password have been defined
    netconf_server.username = "admin"
    netconf_server.password = "password"

    # WHEN connecting using correct credentials
    with connect_ssh(
        host="localhost",
        port=8830,
        username="admin",
        password="password",
    ) as session:
        # THEN expect to be connected
        assert session.session_id


def test_when_connecting_using_username_and_password_then_authentication_fails(
    netconf_server: NetconfServer,
):
    # GIVEN username and password have been defined
    netconf_server.username = "admin"
    netconf_server.password = "password"

    # WHEN connecting using wrong credentials
    with pytest.raises(paramiko.ssh_exception.AuthenticationException) as error:
        with connect_ssh(
            host="localhost",
            port=8830,
            username="foo",
            password="bar",
        ) as session:
            Manager(session=session)

    # THEN expect error
    assert "Authentication failed." in str(error)


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
    with connect_ssh(
        host="localhost",
        port=8830,
        username="admin",
        password=None,
        key_filename=key_filepath,
    ) as session:
        # THEN expect to be connected
        assert session.session_id

def test_when_connecting_using_username_and_wrong_key_then_authentication_fails(
    netconf_server, tmp_path
):
    # GIVEN generated key
    key_filepath = (tmp_path / "key").as_posix()
    key = paramiko.RSAKey.generate(bits=2048)
    key.write_private_key_file(key_filepath)

    # GIVEN SSH username and a different key have been defined
    netconf_server.username = "admin"
    netconf_server.authorized_key = f"foobar"

    # WHEN connecting using wrong key
    with pytest.raises(paramiko.ssh_exception.AuthenticationException) as error:
        with connect_ssh(
            host="localhost",
            port=8830,
            username="foo",
            password=None,
            key_filename=key_filepath,
        ) as session:
            Manager(session=session)

    # THEN expect error
    assert "Authentication failed." in str(error)
