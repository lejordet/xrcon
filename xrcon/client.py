import socket
import time
from functools import wraps
from typing import TYPE_CHECKING, Optional

from .utils import (
    CHALLENGE_PACKET,
    CHALLENGE_RESPONSE_HEADER,
    MAX_PACKET_SIZE,
    PING_Q2_PACKET,
    PING_Q3_PACKET,
    PONG_Q2_PACKET,
    PONG_Q3_PACKET,
    QUAKE_STATUS_PACKET,
    RCON_RESPONSE_HEADER,
    STATUS_RESPONSE_HEADER,
    Player,
    parse_challenge_response,
    parse_rcon_response,
    parse_server_addr,
    parse_status_packet,
    rcon_nosecure_packet,
    rcon_secure_challenge_packet,
    rcon_secure_time_packet,
)


class NotConnected(Exception):
    pass


if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import ParamSpec, TypeVar, cast
    P = ParamSpec('P')
    R = TypeVar('R')


def connection_required(fun: 'Callable[P, R]') -> 'Callable[P, R]':
    @wraps(fun)
    def wrapper(self, *args: 'P.args', **kwargs: 'P.kwargs') -> 'R':
        if self.sock is None:
            raise NotConnected("You should call connect first")
        # Type narrowing: self.sock is not None after this check
        return fun(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


class QuakeProtocol:

    CHALLENGE_TIMEOUT = 3
    player_factory = Player.parse_player

    def __init__(self, host, port, timeout=0.7):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self):
        "Create connection to server"
        family, stype, proto, cname, sockaddr = self.best_connection_params(
            self.host, self.port)
        self.sock = socket.socket(family, stype)
        self.sock.settimeout(self.timeout)
        self.sock.connect(sockaddr)

    @connection_required
    def close(self):
        "Close connection"
        self.sock.close()  # type: ignore[possibly-missing-attribute]
        self.sock = None

    @connection_required
    def read_iterator(self, timeout=3):
        timeout_time = time.time() + timeout
        while time.time() < timeout_time:
            yield self.sock.recv(MAX_PACKET_SIZE)  # type: ignore[possibly-missing-attribute]

        raise TimeoutError("Read timeout")

    @staticmethod
    def best_connection_params(host, port):
        params = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
        for data in params:
            if data[0] == socket.AF_INET:
                return data

        if len(params) > 0:
            return params[0]

    @connection_required
    def getchallenge(self):
        "Return server challenge"
        self.sock.send(CHALLENGE_PACKET)  # type: ignore[possibly-missing-attribute]
        # wait challenge response
        for packet in self.read_iterator(self.CHALLENGE_TIMEOUT):
            if packet.startswith(CHALLENGE_RESPONSE_HEADER):
                return parse_challenge_response(packet)

    @connection_required
    def getstatus_packet(self):
        self.sock.send(QUAKE_STATUS_PACKET)  # type: ignore[possibly-missing-attribute]
        # wait challenge response
        for packet in self.read_iterator(self.CHALLENGE_TIMEOUT):
            if packet.startswith(STATUS_RESPONSE_HEADER):
                return packet

    def getstatus(self):
        packet = self.getstatus_packet()
        if packet is None:
            return None
        return parse_status_packet(packet, self.player_factory)

    def _ping(self, ping_packet, pong_packet, timeout=1):
        self.sock.send(ping_packet)  # type: ignore[possibly-missing-attribute]
        # wait pong packet
        start = time.time()
        try:
            for packet in self.read_iterator(timeout):
                if packet == pong_packet:
                    return time.time() - start
        except TimeoutError:
            return None

    @connection_required
    def ping2(self, timeout=1):
        return self._ping(PING_Q2_PACKET, PONG_Q2_PACKET, timeout)

    @connection_required
    def ping3(self, timeout=1):
        return self._ping(PING_Q3_PACKET, PONG_Q3_PACKET, timeout)

    @classmethod
    def create_by_server_str(cls, server_str, *args, **kwargs):
        host, port = parse_server_addr(server_str)
        return cls(host, port, *args, **kwargs)


class XRcon(QuakeProtocol):

    RCON_NOSECURE = 0
    "Old quake rcon connection"
    RCON_SECURE_TIME = 1
    "secure rcon with time based sign"
    RCON_SECURE_CHALLENGE = 2
    "secure rcon with challenge based sign"

    RCON_TYPES = frozenset([
        RCON_NOSECURE, RCON_SECURE_TIME, RCON_SECURE_CHALLENGE
    ])

    _secure_rcon = RCON_SECURE_TIME

    def __init__(self, host, port, password, secure_rcon=RCON_SECURE_TIME,
                 timeout=0.7):
        """ host --- ip address or domain of server
        port --- udp port of server
        password --- rcon password
        secure_rcon --- type of rcon connection, default secure rcon, use 0
        for old quake servers
        timeout --- socket timeout
        """
        super(XRcon, self).__init__(host, port, timeout)
        self.password = password
        self.secure_rcon = secure_rcon

    @property
    def secure_rcon(self):
        "Type of rcon connection"
        return self._secure_rcon

    @secure_rcon.setter
    def secure_rcon(self, value):
        if value not in self.RCON_TYPES:
            raise ValueError("Bad value of secure_rcon")

        self._secure_rcon = value

    @connection_required
    def send(self, command):
        "Send rcon command to server"
        if self.secure_rcon == self.RCON_NOSECURE:
            self.sock.send(rcon_nosecure_packet(self.password, command))  # type: ignore[possibly-missing-attribute]
        elif self.secure_rcon == self.RCON_SECURE_TIME:
            self.sock.send(rcon_secure_time_packet(self.password, command))  # type: ignore[possibly-missing-attribute]
        elif self.secure_rcon == self.RCON_SECURE_CHALLENGE:
            challenge = self.getchallenge()
            self.sock.send(rcon_secure_challenge_packet(self.password,  # type: ignore[possibly-missing-attribute]
                                                        challenge, command))
        else:
            raise ValueError("Bad value of secure_rcon")

    @connection_required
    def read_once(self, timeout=2):
        for packet in self.read_iterator(timeout):
            if packet.startswith(RCON_RESPONSE_HEADER):
                return parse_rcon_response(packet)

    @connection_required
    def read_untill(self, timeout=1):
        data = []
        try:
            for packet in self.read_iterator(timeout):
                if packet.startswith(RCON_RESPONSE_HEADER):
                    data.append(parse_rcon_response(packet))
        except TimeoutError:
            pass

        if data:
            return b"".join(data)

    @connection_required
    def execute(self, command, timeout=1):
        """Execute rcon command on server and fetch result
        Args:
            command --- executed command
            timeout --- read timeout

        Returns: bytes response
        """
        self.send(command)
        return self.read_untill(timeout)
