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


def test_when_no_requests_made_then_was_called_returns_false():
    # GIVEN netconf server instance
    nc = NetconfServer()

    # WHEN checking if server was called
    result = nc.was_called()

    # THEN expect false
    assert result is False


def test_when_no_requests_made_then_call_count_returns_zero():
    # GIVEN netconf server instance
    nc = NetconfServer()

    # WHEN getting call count
    result = nc.get_call_count()

    # THEN expect zero
    assert result == 0


@patch("paramiko.Channel")
def test_when_request_made_then_was_called_returns_true(mock_channel):
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN mock channel
    mock_channel.sendall = MagicMock()

    # GIVEN configured request and response
    nc.expect_request("get").respond_with("<data/>")

    # WHEN sending a response (to an made up request)
    nc._send_response("<rpc message-id='123'><get/></rpc>", mock_channel)

    # THEN expect was_called to return true
    assert nc.was_called() is True


@patch("paramiko.Channel")
def test_when_multiple_requests_made_then_call_count_returns_correct_number(
    mock_channel,
):
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN mock channel
    mock_channel.sendall = MagicMock()

    # GIVEN configured request and response
    nc.expect_request("get").respond_with("<data/>")

    # WHEN sending multiple responses (simulating multiple requests)
    nc._send_response("<rpc message-id='123'><get/></rpc>", mock_channel)
    nc._send_response("<rpc message-id='124'><get/></rpc>", mock_channel)
    nc._send_response("<rpc message-id='125'><get/></rpc>", mock_channel)

    # THEN expect call count to be 3
    assert nc.get_call_count() == 3


def test_when_no_matching_requests_made_then_request_handler_was_called_returns_false():
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN request handler
    handler = nc.expect_request("get")

    # WHEN checking if handler was called (no requests made)
    result = handler.was_called()

    # THEN expect false
    assert result is False


def test_when_no_matching_requests_made_then_request_handler_call_count_returns_zero():
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN request handler
    handler = nc.expect_request("get")

    # WHEN getting call count (no requests made)
    result = handler.get_call_count()

    # THEN expect zero
    assert result == 0


@patch("paramiko.Channel")
def test_when_matching_request_made_then_request_handler_was_called_returns_true(
    mock_channel,
):
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN request handler
    handler = nc.expect_request("get").respond_with("<data/>")

    # GIVEN mock channel
    mock_channel.sendall = MagicMock()

    # WHEN sending a matching request
    nc._send_response("<rpc message-id='123'><get-config/></rpc>", mock_channel)

    # THEN expect handler was_called to return true
    assert handler.was_called() is True


@patch("paramiko.Channel")
def test_when_multiple_matching_requests_made_then_request_handler_call_count_returns_correct_number(
    mock_channel,
):
    # GIVEN netconf server instance
    nc = NetconfServer()

    # GIVEN edit request handler
    edit_handler = nc.expect_request("edit").respond_with("<data/>")

    # GIVEN get request handler
    get_handler = nc.expect_request("get").respond_with("<data/>")

    # GIVEN mock channel
    mock_channel.sendall = MagicMock()

    # WHEN sending multiple matching requests
    nc._send_response("<rpc message-id='123'><get/></rpc>", mock_channel)
    nc._send_response("<rpc message-id='124'><get/></rpc>", mock_channel)

    # AND sending non-matching request
    nc._send_response("<rpc message-id='125'><edit/></rpc>", mock_channel)

    # THEN expect total calls to be 3
    assert nc.was_called()
    assert nc.get_call_count() == 3

    # THEN expect get handler call count to be 2
    assert get_handler.was_called()
    assert get_handler.get_call_count() == 2

    # THEN expect edit handler to be called once
    assert edit_handler.was_called()
    assert edit_handler.get_call_count() == 1
