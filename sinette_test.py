# MIT License
#
# Copyright (C) 2026 vanous
#
# This file is part of sinette.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sinette
from sacn.receiving.receiver_socket_base import ReceiverSocketBase


def sinette_option(delta: int, value: bytes) -> bytes:
    return bytes((delta << 4 | len(value),)) + value


def sinette_packet(
    universe: int = 1,
    scope: str = "local",
    resource: str = "level",
    levels: bytes = b"\x01\x02\x03",
) -> bytes:
    path = ("sig-net", "v1", scope, resource, str(universe))
    options = b"".join(
        sinette_option(11 if index == 0 else 0, segment.encode("ascii"))
        for index, segment in enumerate(path)
    )
    payload = b"\x01\x01" + len(levels).to_bytes(2, "big") + levels
    return b"\x50\x02\x12\x34" + options + b"\xff" + payload


class SinetteSocketTest(ReceiverSocketBase):
    def __init__(self):
        super().__init__(None)
        self.join_multicast_called = None
        self.start_called = False
        self.stop_called = False

    def start(self):
        self.start_called = True

    def stop(self):
        self.stop_called = True

    def join_multicast(self, multicast_addr):
        self.join_multicast_called = multicast_addr

    def leave_multicast(self, multicast_addr):
        pass

    def call_on_data(self, data):
        self._listener.on_data(data, 0)


def test_sinette_parser_exposes_scope_and_levels():
    packet = sinette.parse_sinette_packet(
        sinette_packet(17, "Hall_A"), expected_scope="Hall_A"
    )
    assert packet.scope == "Hall_A"
    assert packet.universe == 17
    assert packet.dmxData[:3] == (1, 2, 3)
    assert len(packet.dmxData) == 512


def test_sinette_parser_ignores_preview_and_scope_mismatch():
    assert sinette.parse_sinette_packet(sinette_packet(resource="preview")) is None
    assert sinette.parse_sinette_packet(sinette_packet(scope="other")) is None


def test_sinette_receiver_matches_sacn_listener_api():
    socket_instance = SinetteSocketTest()
    receiver = sinette.SinetteReceiver(socket=socket_instance)
    socket_instance._listener = receiver._handler
    received = []

    @receiver.listen_on("universe", universe=1)
    def on_level(packet):
        received.append(packet)

    receiver.join_multicast(1)
    receiver.start()
    socket_instance.call_on_data(sinette_packet())
    receiver.stop()

    assert socket_instance.join_multicast_called == "239.254.0.1"
    assert socket_instance.start_called
    assert socket_instance.stop_called
    assert received[0].dmxData[:3] == (1, 2, 3)
