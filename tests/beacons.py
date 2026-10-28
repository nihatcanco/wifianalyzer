"""Builders for 802.11 information elements, laid out as IEEE Std 802.11 describes them."""

from __future__ import annotations


def ie(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body


def ext(ext_id: int, body: bytes) -> bytes:
    return ie(255, bytes([ext_id]) + body)


def ht_operation(primary: int, info: int) -> bytes:
    return ie(61, bytes([primary, info]) + bytes(20))


def vht_operation(width: int, segment0: int, segment1: int) -> bytes:
    return ie(192, bytes([width, segment0, segment1]) + b"\xfc\xff")


def he_operation(*, vht: bytes | None = None, cohosted: bool = False, six_ghz: bytes | None = None) -> bytes:
    parameters = (1 << 14 if vht else 0) | (1 << 15 if cohosted else 0) | (1 << 17 if six_ghz else 0)
    body = parameters.to_bytes(3, "little") + b"\x01" + b"\xfc\xff"
    body += (vht or b"") + (b"\x03" if cohosted else b"") + (six_ghz or b"")
    return ext(36, body)


def six_ghz_info(primary: int, width_code: int, segment0: int, segment1: int) -> bytes:
    return bytes([primary, width_code, segment0, segment1, 6])


def eht_operation(width_code: int, segment0: int = 0, segment1: int = 0) -> bytes:
    return ext(106, b"\x01" + b"\x44\x44\x44\x44" + bytes([width_code, segment0, segment1]))


def rsn(*akms: int, capabilities: int = 0, oui: bytes = b"\x00\x0f\xac") -> bytes:
    body = b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00\x00\x0f\xac\x04"
    body += len(akms).to_bytes(2, "little") + b"".join(oui + bytes([a]) for a in akms)
    return ie(48, body + capabilities.to_bytes(2, "little"))


def wpa(*akms: int) -> bytes:
    body = b"\x00\x50\xf2\x01" + b"\x01\x00" + b"\x00\x50\xf2\x02" + b"\x01\x00\x00\x50\xf2\x02"
    body += len(akms).to_bytes(2, "little") + b"".join(b"\x00\x50\xf2" + bytes([a]) for a in akms)
    return ie(221, body)


MFP_REQUIRED = 0xC0  # MFPR and MFPC
HT_CAPABILITIES = ie(45, bytes(26))
VHT_CAPABILITIES = ie(191, bytes(12))
HE_CAPABILITIES = ext(35, bytes(20))
EHT_CAPABILITIES = ext(108, bytes(12))
