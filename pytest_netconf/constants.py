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

RPC_REPLY_OK = """<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply message-id="{message_id}" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <ok/> <!-- ok response -->
</rpc-reply>"""

RPC_REPLY_ERROR = """<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply message-id="{message_id}" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <rpc-error>
        <error-type>{type}</error-type>
        <error-tag>{tag}</error-tag>
        <error-severity>error</error-severity>
        <error-message xml:lang="en">{message}</error-message>
    </rpc-error>
</rpc-reply>"""
