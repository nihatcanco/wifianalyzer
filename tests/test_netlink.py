import errno
import socket
import struct
import sys
import threading
import types

import pytest

from wifianalyzer.scanner import netlink
from wifianalyzer.scanner.netlink import (
    GENL_ID_CTRL,
    NLA_F_NESTED,
    NLM_F_ACK_TLVS,
    NLM_F_CAPPED,
    NLM_F_DUMP_INTR,
    NLMSG_DONE,
    NLMSG_ERROR,
    Attrs,
    NetlinkError,
    attr,
    attr_nested,
    attr_str,
    attr_u32,
    parse_attrs,
    read_error,
    split_messages,
)

HEADER = struct.Struct("=IHHII")
FAMILY = 0x1C


def message(kind: int, payload: bytes, *, seq: int, flags: int = 0) -> bytes:
    return HEADER.pack(HEADER.size + len(payload), kind, flags, seq, 0) + payload


def reply(cmd: int, *attrs: bytes, seq: int, flags: int = 0, family: int = FAMILY) -> bytes:
    return message(family, struct.pack("=BBH", cmd, 1, 0) + b"".join(attrs), seq=seq, flags=flags)


def error(code: int, *, seq: int, flags: int = 0, tlvs: bytes = b"") -> bytes:
    echoed = HEADER.pack(HEADER.size + 4, FAMILY, 0, seq, 0) + (b"" if flags & NLM_F_CAPPED else bytes(4))
    return message(NLMSG_ERROR, struct.pack("=i", -code) + echoed + tlvs, seq=seq, flags=flags)


def done(*, seq: int, code: int = 0) -> bytes:
    return message(NLMSG_DONE, struct.pack("=i", -code), seq=seq)


# --- Attributes -----------------------------------------------------------------------


def test_attributes_are_padded_to_four_bytes():
    packed = attr(7, b"abc")
    assert packed == struct.pack("=HH", 7, 7) + b"abc\0"
    assert attr_u32(1, 5) == struct.pack("=HHI", 8, 1, 5)
    assert attr_str(2, "nl80211") == struct.pack("=HH", 12, 2) + b"nl80211\0"


def test_attributes_round_trip_with_nesting():
    data = attr_u32(1, 0xDEADBEEF) + attr_nested(2, attr(1, b"\xfe"), attr_str(2, "wlan0")) + attr(3)
    attrs = parse_attrs(data)
    assert attrs.u32(1) == 0xDEADBEEF
    assert set(attrs) == {1, 2, 3}  # the nested flag is masked out of the type
    inner = attrs.nested(2)
    assert inner.u8(1) == 254
    assert inner.s8(1) == -2
    assert inner.string(2) == "wlan0"
    assert attrs.flag(3)
    assert not attrs.flag(4)
    assert attrs.nested(9) == Attrs()


def test_short_or_truncated_attributes_are_ignored():
    attrs = parse_attrs(attr(1, b"\x01") + struct.pack("=HH", 40, 2) + b"short")
    assert attrs.u32(1) is None  # one byte isn't a u32
    assert 2 not in attrs
    assert parse_attrs(struct.pack("=HH", 2, 1)) == Attrs()  # a length shorter than the header


def test_signed_readers():
    attrs = parse_attrs(attr(1, struct.pack("=i", -5500)) + attr(2, struct.pack("=H", 513)))
    assert attrs.s32(1) == -5500
    assert attrs.u16(2) == 513


def test_nested_flag_is_set_on_nested_attributes():
    kind = struct.unpack_from("=HH", attr_nested(5))[1]
    assert kind == 5 | NLA_F_NESTED


# --- Messages -------------------------------------------------------------------------


def test_split_messages_follows_alignment_and_stops_at_truncation():
    data = reply(1, attr(1, b"a"), seq=3) + reply(2, seq=3) + HEADER.pack(100, FAMILY, 0, 3, 0)
    parts = list(split_messages(data))
    assert [(kind, seq) for kind, _flags, seq, _payload in parts] == [(FAMILY, 3), (FAMILY, 3)]


def test_read_error():
    assert read_error(NLMSG_ERROR, 0, struct.pack("=i", 0)) is None  # an acknowledgement
    plain = read_error(NLMSG_ERROR, 0, struct.pack("=i", -errno.EPERM))
    assert plain.errno == errno.EPERM
    assert plain.strerror == "Operation not permitted"


@pytest.mark.parametrize("capped", [False, True])
def test_read_error_uses_the_kernels_explanation(capped):
    flags = NLM_F_ACK_TLVS | (NLM_F_CAPPED if capped else 0)
    data = error(errno.EINVAL, seq=1, flags=flags, tlvs=attr_str(1, "missing interface"))
    [(kind, msg_flags, _seq, payload)] = split_messages(data)
    found = read_error(kind, msg_flags, payload)
    assert found.errno == errno.EINVAL
    assert found.strerror == "missing interface"


def test_read_error_on_a_failed_dump():
    payload = struct.pack("=i", -errno.EOPNOTSUPP) + attr_str(1, "not supported")
    found = read_error(NLMSG_DONE, NLM_F_ACK_TLVS, payload)
    assert found.errno == errno.EOPNOTSUPP
    assert found.strerror == "not supported"


# --- Talking to a stand-in kernel ------------------------------------------------------


class KernelSocket:
    """One end of a datagram socket pair, posing as a netlink socket."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def bind(self, address):
        pass

    def setsockopt(self, *args):
        pass

    def __getattr__(self, name):
        return getattr(self._sock, name)


@pytest.fixture
def kernel(monkeypatch):
    if sys.platform == "win32":
        pytest.skip("needs Unix datagram sockets")
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    fake = types.SimpleNamespace(AF_NETLINK=16, SOCK_RAW=3, socket=lambda *_: KernelSocket(ours))
    monkeypatch.setattr(netlink, "socket", fake)
    yield theirs
    ours.close()
    theirs.close()


def test_request_collects_the_reply_until_the_acknowledgement(kernel):
    nl = netlink.GenericNetlink()
    kernel.send(reply(7, attr_u32(3, 4), seq=1) + error(0, seq=1))
    [answer] = nl.request(FAMILY, 5, attr_u32(3, 4))
    assert answer.cmd == 7
    assert answer.attrs.u32(3) == 4
    sent = kernel.recv(4096)
    length, kind, flags, seq, _ = HEADER.unpack_from(sent)
    assert (length, kind, seq) == (len(sent), FAMILY, 1)
    assert flags == netlink.NLM_F_REQUEST | netlink.NLM_F_ACK


def test_a_dump_spans_datagrams_and_skips_stale_replies(kernel):
    nl = netlink.GenericNetlink()
    kernel.send(reply(1, seq=0))  # left over from an earlier request
    kernel.send(reply(1, attr_u32(1, 1), seq=1) + reply(1, attr_u32(1, 2), seq=1))
    kernel.send(reply(1, attr_u32(1, 3), seq=1) + done(seq=1))
    answers = nl.request(FAMILY, 32, dump=True)
    assert [a.attrs.u32(1) for a in answers] == [1, 2, 3]
    _, _, flags, _, _ = HEADER.unpack_from(kernel.recv(4096))
    assert flags & netlink.NLM_F_DUMP == netlink.NLM_F_DUMP


def test_an_interrupted_dump_is_repeated(kernel):
    nl = netlink.GenericNetlink()
    kernel.send(reply(1, attr_u32(1, 1), seq=1, flags=NLM_F_DUMP_INTR) + done(seq=1))
    kernel.send(reply(1, attr_u32(1, 2), seq=2) + done(seq=2))
    assert [a.attrs.u32(1) for a in nl.request(FAMILY, 32, dump=True)] == [2]


def test_errors_are_raised(kernel):
    nl = netlink.GenericNetlink()
    kernel.send(error(errno.EPERM, seq=1))
    with pytest.raises(NetlinkError) as raised:
        nl.request(FAMILY, 33)
    assert raised.value.errno == errno.EPERM


def test_a_silent_kernel_times_out(kernel, monkeypatch):
    nl = netlink.GenericNetlink()
    nl._sock.settimeout(0.05)
    with pytest.raises(NetlinkError) as raised:
        nl.request(FAMILY, 5)
    assert raised.value.errno == errno.ETIMEDOUT


def test_resolve_reads_the_family_and_its_multicast_groups(kernel):
    nl = netlink.GenericNetlink()
    groups = attr_nested(
        7,
        attr_nested(1, attr_str(1, "config"), attr_u32(2, 5)),
        attr_nested(2, attr_str(1, "scan"), attr_u32(2, 6)),
    )
    kernel.send(
        reply(1, attr(1, struct.pack("=H", FAMILY)), attr_str(2, "nl80211"), groups, seq=1, family=GENL_ID_CTRL)
    )
    kernel.send(error(0, seq=1))
    family = nl.resolve("nl80211")
    assert family.id == FAMILY
    assert family.groups == {"config": 5, "scan": 6}


def test_wait_for_returns_on_a_matching_notification(kernel):
    nl = netlink.GenericNetlink()
    kernel.send(reply(33, attr_u32(3, 4), seq=0))  # scan started: not what we wait for
    kernel.send(reply(34, attr_u32(3, 9), seq=0))  # results, but for another interface
    kernel.send(reply(34, attr_u32(3, 4), seq=0))
    assert nl.wait_for(lambda m: m.cmd == 34 and m.attrs.u32(3) == 4, timeout=2, cancelled=threading.Event())


def test_wait_for_gives_up_on_timeout_or_cancellation(kernel):
    nl = netlink.GenericNetlink()
    assert not nl.wait_for(lambda m: True, timeout=0.05, cancelled=threading.Event())
    cancelled = threading.Event()
    cancelled.set()
    assert not nl.wait_for(lambda m: True, timeout=5, cancelled=cancelled)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="talks to the Linux kernel")
def test_the_real_kernel_resolves_its_own_controller():
    # nlctrl is always registered, so this checks the transport against a real kernel on any Linux.
    nl = netlink.GenericNetlink()
    try:
        assert nl.resolve("nlctrl").id == GENL_ID_CTRL
        with pytest.raises(NetlinkError) as raised:
            nl.resolve("no-such-family")
        assert raised.value.errno == errno.ENOENT
    finally:
        nl.close()
