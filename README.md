# pytest-netconf

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/nomios-opensource/pytest-netconf/publish.yml)
![Codecov](https://img.shields.io/codecov/c/github/nomios-opensource/pytest-netconf)  
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pytest-netconf)
![PyPI - Downloads](https://img.shields.io/pypi/dm/pytest-netconf)
![GitHub License](https://img.shields.io/github/license/nomios-opensource/pytest-netconf)

A pytest plugin that provides a mock NETCONF (RFC6241/RFC6242) server for local testing. 

`pytest-netconf` is authored by [Adam Kirchberger](https://github.com/adamkirchberger), governed as a [benevolent dictatorship](CODE_OF_CONDUCT.md), and distributed under [license](LICENSE).

## Introduction

Testing NETCONF devices has traditionally required maintaining labs with multiple vendor devices which can be complex and resource-intensive. Additionally, spinning up virtual devices for testing purposes is often time-consuming and too slow for CICD pipelines. This plugin provides a convenient way to mock the behavior and responses of these NETCONF devices.

## Features

- **NETCONF server**, a real SSH server is run locally which enables testing using actual network connections instead of patching.
- **Predefined requests and responses**, define specific NETCONF requests and responses to meet your testing needs.
- **Capability testing**, define specific capabilities you want the server to support and test their responses.
- **Authentication testing**, test error handling for authentication issues (supports password or key auth).
- **Connection testing**, test error handling when tearing down connections unexpectedly.

## NETCONF Clients

The clients below have been tested

- `ncclient` :white_check_mark:
- `netconf-client` :white_check_mark:
- `scrapli-netconf` :white_check_mark:

## Installation

Install using `pip install pytest-netconf` or `poetry add --group dev pytest-netconf`

## Quickstart

The plugin will install a pytest fixture named `netconf_server`, which will start an SSH server with settings you provide, and **only** reply to requests which you define with corresponding responses.

For more use cases see [examples](#examples)


```python
# Configure server settings
netconf_server.username = None  # allow any username
netconf_server.password = None  # allow any password
netconf_server.port = 8830  # default value

# Configure a request and response
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
        </rpc-reply>
        """
    )
```

## Examples

<details>
<summary>Get Config</summary>
<br>

```python
from pytest_netconf import NetconfServer
from ncclient import manager


def test_netconf_get_config(
    netconf_server: NetconfServer,
):
    # GIVEN server request and response
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
```
</details>

<details>
<summary>Authentication Fail</summary>
<br>

```python
from pytest_netconf import NetconfServer
from ncclient import manager
from ncclient.transport.errors import AuthenticationError


def test_netconf_auth_fail(
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
```
</details>

<details>
<summary>Custom Capabilities</summary>
<br>

```python
from pytest_netconf import NetconfServer
from ncclient import manager


def test_netconf_capabilities(
    netconf_server: NetconfServer,
):
    # GIVEN extra capabilities
    netconf_server.capabilities.append("urn:ietf:params:netconf:capability:foo:1.1")
    netconf_server.capabilities.append("urn:ietf:params:netconf:capability:bar:1.1")

    # WHEN receiving server capabilities
    with manager.connect(
        host="localhost",
        port=8830,
        username="admin",
        password="admin",
        hostkey_verify=False,
    ) as m:
        server_capabilities = m.server_capabilities

    # THEN expect to see capabilities
    assert "urn:ietf:params:netconf:capability:foo:1.1" in server_capabilities
    assert "urn:ietf:params:netconf:capability:bar:1.1" in server_capabilities
```
</details>

<details>
<summary>Server Disconnect</summary>
<br>

```python
from pytest_netconf import NetconfServer
from ncclient import manager
from ncclient.transport.errors import TransportError


def test_netconf_server_disconnect(
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
```
</details>

<details>
<summary>Key Auth</summary>
<br>

```python
from pytest_netconf import NetconfServer
from ncclient import manager


def test_netconf_key_auth(
    netconf_server: NetconfServer,
):
    # GIVEN SSH username and authorized key
    netconf_server.username = "admin"
    netconf_server.authorized_key = "ssh-rsa AAAAB3NzaC1yc..."

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
```
</details>


## Versioning

Releases will follow semantic versioning (major.minor.patch). Before 1.0.0 breaking changes can be included in a minor release, therefore we highly recommend pinning this package.

## Contributing

Suggest a [feature]() or report a [bug](). Read our developer [guide](CONTRIBUTING.md).

## License

pytest-netconf is distributed under the Apache 2.0 [license](LICENSE).
