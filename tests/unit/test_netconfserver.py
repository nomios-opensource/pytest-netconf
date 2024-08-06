import pytest
from unittest.mock import patch, MagicMock

from pytest_netconf.netconfserver import NetconfServer
from pytest_netconf.exceptions import RequestError


@pytest.mark.parametrize(
    "prop_name,prop_value",
    [
        ("base_version", "1.1"),
        ("host", "localhost"),
        ("port", 1234),
        ("username", "foo"),
        ("password", "bar"),
        ("authorized_key", "specialkey"),
    ],
)
def test_when_setting_server_settings_then_value_is_returned(prop_name, prop_value):
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN settings property has been set
    setattr(nc, prop_name, prop_value)

    # WHEN accessing property
    val = getattr(nc, prop_name)

    # THEN expect value
    assert val == prop_value

    # THEN expect internal settings instance to also match
    assert getattr(nc.settings, prop_name) == prop_value


def test_when_setting_invalid_server_base_version_then_error_is_raised():
    # GIVEN netconf server instance
    nc = NetconfServer()

    # WHEN setting invalid base version
    with pytest.raises(ValueError) as error:
        nc.base_version = "99"

    # THEN expect error
    assert str(error.value) == "Invalid NETCONF base version 99: must be '1.0' or '1.1'"


@patch("socket.socket", autospec=True)
def test_when_server_bind_port_in_use_error_is_raised(mock_socket):
    # GIVEN socket raises error
    mock_socket.side_effect = OSError(48, "Address already in use")

    # GIVEN netconf server instance
    nc = NetconfServer()
    nc.port = 8830

    # WHEN calling bind socket
    with pytest.raises(OSError) as error:
        nc._bind_socket()

    # THEN expect error
    assert str(error.value) == "could not bind to port 8830"


@patch("socket.socket", autospec=True)
def test_when_server_bind_generic_error_then_error_is_raised(mock_socket):
    # GIVEN socket raises error
    mock_socket.side_effect = OSError(13, "Permission denied")

    # GIVEN netconf server instance
    nc = NetconfServer()
    nc.port = 8830

    # WHEN calling bind socket
    with pytest.raises(OSError) as error:
        nc._bind_socket()

    # THEN expect error
    assert str(error.value) == "[Errno 13] Permission denied"


def test_when_handle_request_has_unknown_error_then_error_is_raised():
    # GIVEN netconf server instance which is running
    nc = NetconfServer()
    nc.running = True

    # GIVEN patched function that raises error
    nc._process_buffer = MagicMock(side_effect=RuntimeError("foo"))

    # WHEN calling handle requests
    with pytest.raises(RequestError) as error:
        nc._handle_requests(MagicMock())

    # THEN expect our error to pass through
    assert str(error.value) == "failed to handle request: foo"


def test_when_process_buffer_receives_base11_missing_size_then_false_is_returned(
    caplog,
):
    # GIVEN netconf server instance which is running
    nc = NetconfServer()
    nc.running = True
    nc._hello_sent = True
    nc.base_version = "1.1"

    # WHEN calling process buffer
    result = nc._process_buffer(buffer=b"999\nfoo\n##\n", channel=MagicMock())

    # THEN expect result to be false
    assert result is False

    # THEN expect log message
    assert "parse error: Invalid content or chunk size format" in caplog.text


def test_when_extract_base11_invalid_length_then_error_is_raised(
    caplog,
):
    # GIVEN netconf server instance which is running
    nc = NetconfServer()

    # WHEN calling extract method
    with pytest.raises(ValueError) as error:
        nc._extract_base11_content_and_length("#999\nfoobar\n##\n")

    # THEN expect error
    assert str(error.value) == "received invalid chunk size expected=6 received=999"


@pytest.mark.parametrize(
    "test_input,expected",
    [
        (
            """
            <rpc message-id="101" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <get-config>
                    <source>
                        <running/>
                    </source>
                </get-config>
            </rpc>
        """,
            "101",
        ),
        (
            """
            <rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <get-config>
                    <source>
                        <running/>
                    </source>
                </get-config>
            </rpc>
        """,
            "unknown",
        ),
        (
            """
            <<invalid xml>>
        """,
            "unknown",
        ),
    ],
    ids=["valid-101", "unknown-missing", "unknown-invalid"],
)
def test_when_extract_message_id_then_string_is_returned(test_input, expected):
    # GIVEN input rpc
    request = test_input

    # GIVEN netconf server instance which is running
    nc = NetconfServer()

    # WHEN extracting message id
    message_id = nc._extract_message_id(request)

    # THEN expect result
    assert message_id == expected
