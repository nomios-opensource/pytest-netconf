from lxml import etree
import pytest
import paramiko
from pytest_netconf import NetconfServer

from scrapli_netconf.driver import NetconfDriver
from scrapli.exceptions import ScrapliConnectionError


@pytest.mark.parametrize("base_version", ["1.0", "1.1"])
def test_when_full_request_and_response_is_defined_then_response_is_returned(
    base_version,
    netconf_server: NetconfServer,
):
    # GIVEN server base version
    netconf_server.base_version = base_version

    # GIVEN server request and response are defined
    netconf_server.expect_request(
        "\n"  # scrapli seems to send new line for 1.0
        if base_version == "1.0"
        else ""
        "<?xml version='1.0' encoding='utf-8'?>\n"
        '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="{message_id}">'
        "<get-config><source><running/></source></get-config>"
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
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="admin",
        auth_password="admin",
        auth_strict_key=False,
        strip_namespaces=True,
    ) as conn:
        response = conn.get_config(source="running").xml_result

    # THEN expect response
    assert (
        """<interfaces>
  <interface>
    <name>eth0</name>
  </interface>
</interfaces>
"""
        == etree.tostring(
            response.find(".//data/"),
            pretty_print=True,
        ).decode()
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
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="admin",
        auth_password="admin",
        auth_strict_key=False,
        strip_namespaces=True,
    ) as conn:
        response = conn.get_config(source="running").xml_result

    # THEN expect response
    assert (
        """<interfaces>
  <interface>
    <name>eth0</name>
  </interface>
</interfaces>
"""
        == etree.tostring(
            response.find(".//data/"),
            pretty_print=True,
        ).decode()
    )


def test_when_unexpected_request_received_then_error_response_is_returned(
    netconf_server: NetconfServer,
):
    # GIVEN no server request and response are defined
    netconf_server

    # WHEN fetching rpc response from server
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="admin",
        auth_password="admin",
        auth_strict_key=False,
        timeout_ops=5,
    ) as conn:
        response = conn.get_config(source="running").result

    # THEN expect error response
    assert (
        response
        == """<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="101">
  <rpc-error>
    <error-type>rpc</error-type>
    <error-tag>operation-failed</error-tag>
    <error-severity>error</error-severity>
    <error-message xml:lang="en">pytest-netconf: requested rpc is unknown and has no response defined</error-message>
  </rpc-error>
</rpc-reply>
"""
    )


def test_when_server_stops_then_client_error_is_raised(
    netconf_server: NetconfServer,
):
    # GIVEN netconf connection
    with pytest.raises(ScrapliConnectionError) as error:
        with NetconfDriver(
            host="localhost",
            port=8830,
            auth_username="admin",
            auth_password="admin",
            auth_strict_key=False,
        ) as conn:
            # WHEN server stops
            netconf_server.stop()
            conn.get_config()  # and a request is attempted

    # THEN expect error
    assert (
        str(error.value)
        == "encountered EOF reading from transport; typically means the device closed the connection"
    )


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
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="admin",
        auth_password="admin",
        auth_strict_key=False,
    ) as conn:
        server_capabilities = conn.server_capabilities

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
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="foo",
        auth_password="bar",
        auth_strict_key=False,
    ) as conn:
        # THEN expect to be connected
        assert conn.isalive()


def test_when_connecting_using_username_and_password_then_authentication_passes(
    netconf_server: NetconfServer,
):
    # GIVEN username and password have been defined
    netconf_server.username = "admin"
    netconf_server.password = "password"

    # WHEN connecting using correct credentials
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="admin",
        auth_password="password",
        auth_strict_key=False,
    ) as conn:
        # THEN expect to be connected
        assert conn.isalive()


def test_when_connecting_using_username_and_password_then_authentication_fails(
    netconf_server: NetconfServer,
):
    # GIVEN username and password have been defined
    netconf_server.username = "admin"
    netconf_server.password = "password"

    # WHEN connecting using wrong credentials
    with pytest.raises(ScrapliConnectionError) as error:
        with NetconfDriver(
            host="localhost",
            port=8830,
            auth_username="foo",
            auth_password="bar",
            auth_strict_key=False,
        ):
            pass

    # THEN expect error
    assert "permission denied, please try again." in str(error)


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
    with NetconfDriver(
        host="localhost",
        port=8830,
        auth_username="admin",
        auth_private_key=key_filepath,
        auth_strict_key=False,
    ) as conn:
        # THEN expect to be connected
        assert conn.isalive()
