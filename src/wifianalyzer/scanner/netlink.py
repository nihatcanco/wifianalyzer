"""Just enough generic netlink to talk to nl80211, the Linux kernel's interface to Wi-Fi drivers.

A netlink socket connects a process to the kernel of the same machine. Nothing sent on one
leaves the computer. The wire format is described in the kernel's Documentation/userspace-api/netlink.
"""

from __future__ import annotations

import contextlib
import errno
import os
import select
import socket
import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from threading import Event

NETLINK_GENERIC = 16
SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1
NETLINK_EXT_ACK = 11

NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_DUMP_INTR = 0x10
NLM_F_DUMP = 0x300
NLM_F_CAPPED = 0x100  # on errors: the echoed request is only its header
NLM_F_ACK_TLVS = 0x200  # on errors: extended ack attributes follow
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSGERR_ATTR_MSG = 1

NLA_F_NESTED = 1 << 15
NLA_TYPE_MASK = (1 << 14) - 1

GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

_HEADER = struct.Struct("=IHHII")  # struct nlmsghdr: length, type, flags, sequence, port
_GENL_HEADER = struct.Struct("=BBH")  # struct genlmsghdr: command, version, reserved
_ATTR_HEADER = struct.Struct("=HH")  # struct nlattr: length, type
_RECEIVE_SIZE = 1 << 16
_REPLY_TIMEOUT = 5.0
_DUMP_ATTEMPTS = 3


def _align(length: int) -> int:
    return (length + 3) & ~3


# --- Attributes -----------------------------------------------------------------------


def attr(kind: int, payload: bytes = b"") -> bytes:
    length = _ATTR_HEADER.size + len(payload)
    return _ATTR_HEADER.pack(length, kind) + payload + bytes(_align(length) - length)


def attr_u32(kind: int, value: int) -> bytes:
    return attr(kind, struct.pack("=I", value))


def attr_str(kind: int, value: str) -> bytes:
    return attr(kind, value.encode() + b"\0")


def attr_nested(kind: int, *children: bytes) -> bytes:
    return attr(kind | NLA_F_NESTED, b"".join(children))


class Attrs(dict[int, bytes]):
    """Attributes by type, with readers for the payload types netlink uses."""

    def _number(self, kind: int, fmt: str) -> int | None:
        payload = self.get(kind)
        size = struct.calcsize(fmt)
        return None if payload is None or len(payload) < size else int(struct.unpack_from(fmt, payload)[0])

    def u8(self, kind: int) -> int | None:
        return self._number(kind, "=B")

    def s8(self, kind: int) -> int | None:
        return self._number(kind, "=b")

    def u16(self, kind: int) -> int | None:
        return self._number(kind, "=H")

    def u32(self, kind: int) -> int | None:
        return self._number(kind, "=I")

    def s32(self, kind: int) -> int | None:
        return self._number(kind, "=i")

    def string(self, kind: int) -> str | None:
        payload = self.get(kind)
        return None if payload is None else payload.split(b"\0", 1)[0].decode("utf-8", errors="replace")

    def nested(self, kind: int) -> Attrs:
        """The attributes nested in ``kind``, empty when it's missing."""
        return parse_attrs(self.get(kind, b""))

    def flag(self, kind: int) -> bool:
        return kind in self


def parse_attrs(data: bytes) -> Attrs:
    attrs = Attrs()
    offset = 0
    while offset + _ATTR_HEADER.size <= len(data):
        length, kind = _ATTR_HEADER.unpack_from(data, offset)
        if length < _ATTR_HEADER.size or offset + length > len(data):
            break
        attrs[kind & NLA_TYPE_MASK] = data[offset + _ATTR_HEADER.size : offset + length]
        offset += _align(length)
    return attrs


# --- Messages -------------------------------------------------------------------------


@dataclass(frozen=True)
class Message:
    """A generic netlink message: its command and attributes."""

    family: int
    flags: int
    seq: int
    cmd: int
    attrs: Attrs


class NetlinkError(OSError):
    """The kernel rejected a request. ``errno`` says why."""


def pack_request(family: int, cmd: int, attrs: bytes, *, seq: int, flags: int, version: int) -> bytes:
    payload = _GENL_HEADER.pack(cmd, version, 0) + attrs
    return _HEADER.pack(_HEADER.size + len(payload), family, flags, seq, 0) + payload


def split_messages(data: bytes) -> Iterator[tuple[int, int, int, bytes]]:
    """The (type, flags, sequence number, payload) of each message in a datagram."""
    offset = 0
    while offset + _HEADER.size <= len(data):
        length, kind, flags, seq, _port = _HEADER.unpack_from(data, offset)
        if length < _HEADER.size or offset + length > len(data):
            break
        yield kind, flags, seq, data[offset + _HEADER.size : offset + length]
        offset += _align(length)


def parse_message(kind: int, flags: int, seq: int, payload: bytes) -> Message | None:
    if len(payload) < _GENL_HEADER.size:
        return None
    cmd, _version, _reserved = _GENL_HEADER.unpack_from(payload)
    return Message(kind, flags, seq, cmd, parse_attrs(payload[_GENL_HEADER.size :]))


def read_error(kind: int, flags: int, payload: bytes) -> NetlinkError | None:
    """The error an NLMSG_ERROR or NLMSG_DONE message reports, or None for success."""
    if len(payload) < 4:
        return None
    code = -struct.unpack_from("=i", payload)[0]
    if code <= 0:
        return None
    text = None
    if flags & NLM_F_ACK_TLVS:
        # Extended ack attributes follow the error code. NLMSG_ERROR echoes the request first.
        echoed = 0
        if kind == NLMSG_ERROR and len(payload) >= 4 + _HEADER.size:
            echoed = _HEADER.size if flags & NLM_F_CAPPED else _align(_HEADER.unpack_from(payload, 4)[0])
        text = parse_attrs(payload[4 + echoed :]).string(NLMSGERR_ATTR_MSG)
    return NetlinkError(code, text or os.strerror(code))


# --- Sockets --------------------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    id: int
    groups: dict[str, int]
    """Multicast group IDs by name."""


class _DumpInterruptedError(Exception):
    """The data changed while the kernel was dumping it, so the dump may be inconsistent."""


class GenericNetlink:
    """A generic netlink socket. Requests on it run one at a time."""

    def __init__(self) -> None:
        # AF_NETLINK only exists on Linux, the only platform that constructs this class.
        self._sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)  # type: ignore[attr-defined,unused-ignore]
        try:
            self._sock.bind((0, 0))
            self._sock.settimeout(_REPLY_TIMEOUT)
            # Ask for the kernel's error explanations; older kernels don't have them.
            with contextlib.suppress(OSError):
                self._sock.setsockopt(SOL_NETLINK, NETLINK_EXT_ACK, 1)
        except BaseException:
            self._sock.close()
            raise
        self._seq = 0

    def close(self) -> None:
        self._sock.close()

    def resolve(self, name: str) -> Family:
        """Look up a generic netlink family, such as ``nl80211``, by name."""
        replies = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attr_str(CTRL_ATTR_FAMILY_NAME, name), version=1)
        if not replies or (family := replies[0].attrs.u16(CTRL_ATTR_FAMILY_ID)) is None:
            raise NetlinkError(errno.ENOENT, f"no {name} family")
        groups = {}
        for raw in replies[0].attrs.nested(CTRL_ATTR_MCAST_GROUPS).values():
            group = parse_attrs(raw)
            group_name, group_id = group.string(CTRL_ATTR_MCAST_GRP_NAME), group.u32(CTRL_ATTR_MCAST_GRP_ID)
            if group_name and group_id is not None:
                groups[group_name] = group_id
        return Family(family, groups)

    def request(self, family: int, cmd: int, *attrs: bytes, dump: bool = False, version: int = 0) -> list[Message]:
        """Send a request and collect its replies; a dump returns one message per object."""
        for _ in range(_DUMP_ATTEMPTS if dump else 1):
            try:
                return self._exchange(family, cmd, b"".join(attrs), dump=dump, version=version)
            except _DumpInterruptedError:
                continue
        return self._exchange(family, cmd, b"".join(attrs), dump=dump, version=version, accept_interrupted=True)

    def _exchange(
        self, family: int, cmd: int, attrs: bytes, *, dump: bool, version: int, accept_interrupted: bool = False
    ) -> list[Message]:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        seq = self._seq
        # A dump ends with NLMSG_DONE; other requests ask for an acknowledgement to end them.
        flags = NLM_F_REQUEST | (NLM_F_DUMP if dump else NLM_F_ACK)
        self._sock.send(pack_request(family, cmd, attrs, seq=seq, flags=flags, version=version))
        replies: list[Message] = []
        interrupted = False
        while True:
            try:
                data = self._sock.recv(_RECEIVE_SIZE)
            except TimeoutError:
                raise NetlinkError(errno.ETIMEDOUT, "the kernel didn't reply") from None
            for kind, msg_flags, msg_seq, payload in split_messages(data):
                if msg_seq != seq:
                    continue  # a late reply to an earlier request
                if kind in (NLMSG_ERROR, NLMSG_DONE):
                    error = read_error(kind, msg_flags, payload)
                    if error is not None:
                        raise error
                    if interrupted and not accept_interrupted:
                        raise _DumpInterruptedError
                    return replies
                interrupted = interrupted or bool(msg_flags & NLM_F_DUMP_INTR)
                message = parse_message(kind, msg_flags, msg_seq, payload)
                if message is not None:
                    replies.append(message)

    def subscribe(self, group: int) -> None:
        """Receive the multicast notifications of ``group``, such as nl80211's ``scan``."""
        self._sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, group)

    def wait_for(self, match: Callable[[Message], bool], timeout: float, cancelled: Event) -> bool:
        """Wait for a notification that ``match`` accepts. False on timeout or cancellation."""
        deadline = time.monotonic() + timeout
        while not cancelled.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            ready, _, _ = select.select([self._sock], [], [], min(remaining, 0.25))
            if not ready:
                continue
            try:
                data = self._sock.recv(_RECEIVE_SIZE)
            except OSError as e:
                if e.errno == errno.ENOBUFS:  # notifications were dropped; later ones still count
                    continue
                raise
            for kind, flags, seq, payload in split_messages(data):
                if kind in (NLMSG_ERROR, NLMSG_DONE):
                    continue
                message = parse_message(kind, flags, seq, payload)
                if message is not None and match(message):
                    return True
        return False
