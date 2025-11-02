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
