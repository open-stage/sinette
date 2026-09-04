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

import socket
import threading
import time
from typing import Dict, List, Optional, Tuple

from sacn.receiving.receiver_socket_base import (
    ReceiverSocketBase,
    ReceiverSocketListener,
)

SINETTE_LISTEN_ON_OPTIONS = ("availability", "universe")
SINETTE_LEVEL_TID = 0x0101
SINETTE_URI_ROOT = "sig-net"
SINETTE_RECEIVER_THREAD_NAME = "Sinette input/receiver thread"


class SinettePacketError(ValueError):
    pass


class SinetteDataPacket:
    """Decoded Sinette level data delivered to receiver listeners."""

    def __init__(self, version: str, scope: str, universe: int, dmx_data: bytes):
        if not isinstance(version, str) or not version:
            raise ValueError("version must be a non-empty string")
        if not isinstance(scope, str) or not scope:
            raise ValueError("scope must be a non-empty string")
        if not isinstance(universe, int) or universe not in range(1, 64000):
            raise ValueError("universe must be [1-63999]")
        if len(dmx_data) not in range(1, 513):
            raise ValueError("dmx_data must contain 1-512 bytes")
        if not all(
            isinstance(value, int) and value in range(256) for value in dmx_data
        ):
            raise ValueError("dmx_data must contain byte values")
        self.version = version
        self.scope = scope
        self.universe = universe
        self.dmxData = tuple(dmx_data) + (0,) * (512 - len(dmx_data))

    @property
    def levels(self) -> tuple:
        return self.dmxData


def sinette_multicast_address(universe: int) -> str:
    if not isinstance(universe, int) or universe not in range(1, 64000):
        raise ValueError("universe must be [1-63999]")
    group_number = ((universe - 1) % 109) + 1
    return f"239.254.0.{group_number}"


def _sinette_extended_value(data: bytes, offset: int, nibble: int) -> Tuple[int, int]:
    if nibble < 13:
        return nibble, 0
    if nibble == 13:
        if offset >= len(data):
            raise SinettePacketError("missing extended option byte")
        return 13 + data[offset], 1
    if nibble == 14:
        if offset + 1 >= len(data):
            raise SinettePacketError("missing extended option word")
        return 269 + int.from_bytes(data[offset : offset + 2], "big"), 2
    raise SinettePacketError("reserved option nibble")


def _sinette_options(data: bytes, offset: int) -> Tuple[List[str], bytes]:
    option_number = 0
    uri_segments = []
    while offset < len(data):
        if data[offset] == 0xFF:
            return uri_segments, data[offset + 1 :]
        header = data[offset]
        offset += 1
        delta, delta_size = _sinette_extended_value(data, offset, header >> 4)
        offset += delta_size
        length, length_size = _sinette_extended_value(data, offset, header & 0x0F)
        offset += length_size
        option_number += delta
        if offset + length > len(data):
            raise SinettePacketError("option exceeds packet length")
        option_value = data[offset : offset + length]
        if option_number == 11:
            try:
                uri_segments.append(option_value.decode("ascii"))
            except UnicodeDecodeError as error:
                raise SinettePacketError("URI path is not ASCII") from error
        offset += length
    return uri_segments, b""


def parse_sinette_packet(
    data: bytes, expected_version: str = "v1", expected_scope: str = "local"
) -> Optional[SinetteDataPacket]:
    if len(data) < 4:
        raise SinettePacketError("packet is shorter than the CoAP header")
    version = data[0] >> 6
    message_type = (data[0] >> 4) & 0x03
    token_length = data[0] & 0x0F
    if version != 1 or message_type != 1 or data[1] != 0x02:
        raise SinettePacketError("unsupported CoAP header")
    if token_length > 8 or 4 + token_length > len(data):
        raise SinettePacketError("invalid token length")

    uri_segments, payload = _sinette_options(data, 4 + token_length)
    if len(uri_segments) != 5 or uri_segments[0] != SINETTE_URI_ROOT:
        return None
    packet_version, packet_scope = uri_segments[1:3]
    if (
        packet_version != expected_version
        or packet_scope != expected_scope
        or uri_segments[3] != "level"
    ):
        return None
    try:
        universe = int(uri_segments[4], 10)
    except ValueError:
        raise SinettePacketError("invalid universe") from None
    if universe not in range(1, 64000) or str(universe) != uri_segments[4]:
        raise SinettePacketError("invalid universe")

    offset = 0
    while offset < len(payload):
        if len(payload) - offset < 4:
            raise SinettePacketError("incomplete TLV header")
        tid = int.from_bytes(payload[offset : offset + 2], "big")
        length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4
        if offset + length > len(payload):
            raise SinettePacketError("TLV exceeds payload length")
        value = payload[offset : offset + length]
        offset += length
        if tid == SINETTE_LEVEL_TID:
            if len(value) not in range(1, 513):
                raise SinettePacketError("level data must contain 1-512 bytes")
            return SinetteDataPacket(packet_version, packet_scope, universe, value)
    return None


class SinetteReceiverSocket(ReceiverSocketBase):
    def __init__(
        self, listener: ReceiverSocketListener, bind_address: str, bind_port: int
    ):
        super().__init__(listener)
        self._bind_address = bind_address
        self._socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(
            ("", bind_port) if bind_address == "0.0.0.0" else (bind_address, bind_port)
        )

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._sinette_receive_loop, name=SINETTE_RECEIVER_THREAD_NAME
        )
        self._thread.start()

    def _sinette_receive_loop(self) -> None:
        self._socket.settimeout(0.1)
        self._enabled_flag = True
        while self._enabled_flag:
            self._listener.on_periodic_callback(time.time())
            try:
                packet_data = self._socket.recv(2048)
            except socket.timeout:
                continue
            self._listener.on_data(packet_data, time.time())

    def stop(self) -> None:
        self._enabled_flag = False
        try:
            self._thread.join()
            self._socket.close()
        except AttributeError:
            pass

    def join_multicast(self, multicast_addr: str) -> None:
        self._socket.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_ADD_MEMBERSHIP,
            socket.inet_aton(multicast_addr) + socket.inet_aton(self._bind_address),
        )

    def leave_multicast(self, multicast_addr: str) -> None:
        try:
            self._socket.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_DROP_MEMBERSHIP,
                socket.inet_aton(multicast_addr) + socket.inet_aton(self._bind_address),
            )
        except OSError:
            pass


class SinetteReceiverHandler(ReceiverSocketListener):
    def __init__(
        self,
        bind_address: str,
        bind_port: int,
        listener,
        version: str,
        scope: str,
        socket: ReceiverSocketBase = None,
    ):
        self.socket = socket or SinetteReceiverSocket(self, bind_address, bind_port)
        self._listener = listener
        self._version = version
        self._scope = scope
        self._known_universes: Dict[int, bool] = {}

    def on_data(self, data: bytes, current_time: float) -> None:
        try:
            packet = parse_sinette_packet(data, self._version, self._scope)
        except SinettePacketError:
            return
        if packet is None:
            return
        if packet.universe not in self._known_universes:
            self._known_universes[packet.universe] = True
            self._listener.on_availability_change(packet.universe, "available")
        self._listener.on_dmx_data_change(packet)

    def on_periodic_callback(self, current_time: float) -> None:
        pass

    def get_possible_universes(self) -> List[int]:
        return list(self._known_universes)


class SinetteReceiver:
    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        bind_port: int = 5683,
        version: str = "v1",
        scope: str = "local",
        socket: ReceiverSocketBase = None,
    ):
        self._callbacks: dict = {}
        self._handler = SinetteReceiverHandler(
            bind_address, bind_port, self, version, scope, socket
        )

    def on_availability_change(self, universe: int, changed: str) -> None:
        for callback in self._callbacks.get("availability", []):
            callback(universe=universe, changed=changed)

    def on_dmx_data_change(self, packet: SinetteDataPacket) -> None:
        for callback in self._callbacks.get(packet.universe, []):
            callback(packet)

    def listen_on(self, trigger: str, **kwargs) -> callable:
        def decorator(function):
            self.register_listener(trigger, function, **kwargs)
            return function

        return decorator

    def register_listener(self, trigger: str, function: callable, **kwargs) -> None:
        if trigger not in SINETTE_LISTEN_ON_OPTIONS:
            raise TypeError(f'The given trigger "{trigger}" is not a valid one!')
        callback_key = kwargs.get("universe") if trigger == "universe" else trigger
        if trigger == "universe" and callback_key is None:
            raise TypeError("universe is required for universe listeners")
        self._callbacks.setdefault(callback_key, []).append(function)

    def remove_listener(self, function: callable) -> None:
        for callbacks in self._callbacks.values():
            while function in callbacks:
                callbacks.remove(function)

    def remove_listener_from_universe(self, universe: int) -> None:
        self._callbacks.pop(universe, None)

    def join_multicast(self, universe: int) -> None:
        self._handler.socket.join_multicast(sinette_multicast_address(universe))

    def leave_multicast(self, universe: int) -> None:
        self._handler.socket.leave_multicast(sinette_multicast_address(universe))

    def start(self) -> None:
        self.stop()
        self._handler.socket.start()

    def stop(self) -> None:
        self._handler.socket.stop()

    def get_possible_universes(self) -> Tuple[int, ...]:
        return tuple(self._handler.get_possible_universes())

    def __del__(self):
        self.stop()
