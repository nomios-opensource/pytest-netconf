from pytest_netconf import NetconfServer

from ncclient import manager


def test_when_server_restarted_then_connection_passes(netconf_server: NetconfServer):
    # GIVEN initial connection to server
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        assert m.connected

    # WHEN server is stopped and then started again
    netconf_server.stop()
    netconf_server.start()

    # THEN expect reconnection to succeed
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        assert m.connected


def test_when_server_started_twice_then_no_error_occurs(netconf_server: NetconfServer):
    # GIVEN server is running
    assert netconf_server.running

    # WHEN attempting to start the server again
    netconf_server.start()

    # THEN server remains running and no errors occur
    assert netconf_server.running

def test_when_server_stopped_twice_then_no_error_occurs(netconf_server: NetconfServer):
    # GIVEN server is stopped
    netconf_server.stop()
    assert not netconf_server.running

    # WHEN attempting to stop the server again
    netconf_server.stop()

    # THEN server remains stopped and no errors occur
    assert not netconf_server.running


def test_when_server_stopped_without_connection(netconf_server: NetconfServer):
    # GIVEN server is running
    assert netconf_server.running

    # GIVEN no connection attempt is made

    # WHEN stopping the server
    netconf_server.stop()

    # THEN server stops cleanly
    assert not netconf_server.running


def test_when_checking_call_count_then_close_and_hello_not_included(netconf_server):
    # GIVEN server request and response
    handler = netconf_server.expect_request(
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
            </data>
        </rpc-reply>
        """
    )

    # WHEN fetching rpc response from server
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        m.get_config(source="running").data_xml

    # THEN expect calls to be made
    assert netconf_server.was_called()
    assert netconf_server.get_call_count() == 1
    assert handler.was_called()
    assert handler.get_call_count() == 1
