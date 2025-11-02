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


def test_when_server_stopped_without_connection(netconf_server: NetconfServer):
    # GIVEN server is running
    assert netconf_server.running

    # GIVEN no connection attempt is made

    # WHEN stopping the server
    netconf_server.stop()

    # THEN server stops cleanly
    assert not netconf_server.running
