"""802.11 information elements: what an access point advertises about itself in its beacons.

Windows and Linux report scanned networks with these elements attached, unparsed. This module
reads the channel width, security and Wi-Fi standard from them. Clause numbers refer to IEEE
Std 802.11-2020; the EHT elements are from 802.11be-2024.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Band

# Element IDs (9.4.2.1). Elements with ID 255 carry an extension ID in their first byte, and
# are stored here under 256 + that ID.
SSID = 0
SUPPORTED_RATES = 1
COUNTRY = 7
HT_CAPABILITIES = 45
RSN = 48
EXTENDED_RATES = 50
HT_OPERATION = 61
VHT_CAPABILITIES = 191
VHT_OPERATION = 192
VENDOR_SPECIFIC = 221
_EXTENSION = 255
HE_CAPABILITIES = 256 + 35
HE_OPERATION = 256 + 36
EHT_OPERATION = 256 + 106
EHT_CAPABILITIES = 256 + 108

IEEE_OUI = b"\x00\x0f\xac"
MICROSOFT_OUI = b"\x00\x50\xf2"
WPA_OUI_TYPE = 1  # Microsoft's WPA element: the pre-standard version of RSN

# AKM suite types under the IEEE OUI (Table 9-151).
_AKM_8021X = 1
_AKM_8021X_SHA256 = 5
_ENTERPRISE_AKMS = frozenset({1, 3, 5, 11, 12, 13, 14, 15, 16, 17})
_SUITE_B_192_AKMS = frozenset({12, 13})
_SAE_AKMS = frozenset({8, 9, 24, 25})
_PSK_AKMS = frozenset({2, 4, 6, 19, 20})
_OWE_AKM = 18
_MFP_REQUIRED = 1 << 6  # RSN Capabilities bit 6

# OFDM rates (6 to 54 Mb/s) in the 500 kb/s units of the Supported Rates element.
_OFDM_RATES = frozenset({12, 18, 24, 36, 48, 72, 96, 108})


class Elements:
    """The elements of one beacon or probe response, in the order they were sent."""

    def __init__(self, data: bytes) -> None:
        self._items: list[tuple[int, bytes]] = []
        offset = 0
        while offset + 2 <= len(data):
            eid, length = data[offset], data[offset + 1]
            body = data[offset + 2 : offset + 2 + length]
            if len(body) < length:
                break  # truncated; keep the complete elements before it
            if eid != _EXTENSION:
                self._items.append((eid, body))
            elif body:
                self._items.append((256 + body[0], body[1:]))
            offset += 2 + length

    def get(self, eid: int) -> bytes | None:
        """Body of the first element with this ID."""
        return next((body for i, body in self._items if i == eid), None)

    def vendor(self, oui: bytes, kind: int) -> bytes | None:
        """Body of a vendor-specific element, after its OUI and type byte."""
        prefix = oui + bytes([kind])
        return next(
            (body[len(prefix) :] for i, body in self._items if i == VENDOR_SPECIFIC and body.startswith(prefix)),
            None,
        )


@dataclass(frozen=True)
class Advertised:
    """What a network's elements say about it."""

    ssid: str | None
    width: int
    phy: str
    security: str
    country: str | None


def parse(data: bytes, band: Band, *, privacy: bool) -> Advertised:
    """Read a network's elements.

    ``privacy`` is the Privacy bit of the network's capability information, which is all that
    distinguishes WEP from an open network.
    """
    elements = Elements(data)
    return Advertised(
        ssid=decode_ssid(elements.get(SSID)),
        width=channel_width(elements, band),
        phy=standard(elements, band),
        security=security(elements, privacy=privacy),
        country=country(elements),
    )


def decode_ssid(raw: bytes | None) -> str | None:
    """A network name from its bytes, or None for a hidden network, which sends an empty or zeroed one."""
    if not raw or not raw.strip(b"\0"):
        return None
    # Names are usually UTF-8, but nothing enforces it.
    return raw.decode("utf-8", errors="replace")


# --- Channel width --------------------------------------------------------------------


def channel_width(elements: Elements, band: Band) -> int:
    """The width in MHz the network transmits on.

    80+80 MHz networks are reported as 80 MHz wide: only their primary segment is modelled.
    """
    if band is Band.GHZ_6:
        width = _he_6ghz_width(elements)
    elif band is Band.GHZ_5:
        width = _vht_width(elements) or _ht_width(elements)
    else:
        width = _ht_width(elements)
    # EHT only describes the channel when it's wider than the older elements can say, e.g. 320 MHz.
    return max(width, _eht_width(elements) or 0)


def _ht_width(elements: Elements) -> int:
    """20 or 40 MHz, from the HT Operation element (9.4.2.56)."""
    body = elements.get(HT_OPERATION)
    if body is None or len(body) < 2:
        return 20
    secondary = body[1] & 0b11  # 1: above the primary channel, 3: below, 0: none
    any_width = body[1] & 0b100  # STA Channel Width
    return 40 if any_width and secondary in (1, 3) else 20


def _vht_width(elements: Elements) -> int | None:
    """80 or 160 MHz from the VHT Operation element (9.4.2.158), or None if it says 20/40."""
    info = elements.get(VHT_OPERATION)
    if info is None:
        info, _ = _he_operation(elements)  # HE Operation can carry the same fields instead
    if info is None or len(info) < 3:
        return None
    width, segment0, segment1 = info[0], info[1], info[2]
    if width == 1:
        # Segment 1 is the 160 MHz center when it is 8 channels from segment 0; further away,
        # it's the second half of an 80+80 MHz channel.
        return 160 if segment1 and abs(segment1 - segment0) == 8 else 80
    if width == 2:  # deprecated encoding of 160 MHz
        return 160
    if width == 3:  # deprecated encoding of 80+80 MHz
        return 80
    return None


def _he_operation(elements: Elements) -> tuple[bytes | None, bytes | None]:
    """The optional VHT and 6 GHz operation fields of the HE Operation element (9.4.2.249)."""
    body = elements.get(HE_OPERATION)
    if body is None or len(body) < 6:
        return None, None
    parameters = int.from_bytes(body[:3], "little")
    offset = 6  # HE Operation Parameters (3), BSS Color Information (1), Basic HE-MCS And NSS Set (2)
    vht = six_ghz = None
    if parameters & (1 << 14):  # VHT Operation Information Present
        vht = body[offset : offset + 3]
        offset += 3
    if parameters & (1 << 15):  # Co-Hosted BSS: a Max Co-Hosted BSSID Indicator byte follows
        offset += 1
    if parameters & (1 << 17):  # 6 GHz Operation Information Present
        six_ghz = body[offset : offset + 5]
    return (vht if vht and len(vht) == 3 else None), (six_ghz if six_ghz and len(six_ghz) == 5 else None)


def _he_6ghz_width(elements: Elements) -> int:
    """Width of a 6 GHz network, from the 6 GHz Operation Information of its HE Operation element."""
    _, info = _he_operation(elements)
    if info is None:
        return 20
    # Primary Channel, Control, Channel Center Frequency Segment 0 and 1, Minimum Rate.
    code = info[1] & 0b11
    if code < 3:
        return (20, 40, 80)[code]
    segment0, segment1 = info[2], info[3]
    return 160 if not segment1 or abs(segment1 - segment0) == 8 else 80


def _eht_width(elements: Elements) -> int | None:
    """Width from the EHT Operation element, when it includes EHT Operation Information."""
    body = elements.get(EHT_OPERATION)
    # EHT Operation Parameters (1), Basic EHT-MCS And NSS Set (4), then Control, CCFS0 and CCFS1.
    if body is None or len(body) < 8 or not body[0] & 0b1:
        return None
    return {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}.get(body[5] & 0b111)


# --- Wi-Fi standard -------------------------------------------------------------------


def standard(elements: Elements, band: Band) -> str:
    """The newest standard the network supports, e.g. ``802.11ax``."""
    if elements.get(EHT_CAPABILITIES) is not None:
        return "802.11be"
    if elements.get(HE_CAPABILITIES) is not None or band is Band.GHZ_6:
        return "802.11ax"
    # Some 2.4 GHz access points advertise VHT too, but 802.11ac is a 5 GHz standard.
    if band is Band.GHZ_5 and elements.get(VHT_CAPABILITIES) is not None:
        return "802.11ac"
    if elements.get(HT_CAPABILITIES) is not None:
        return "802.11n"
    if band is Band.GHZ_5:
        return "802.11a"
    rates = (elements.get(SUPPORTED_RATES) or b"") + (elements.get(EXTENDED_RATES) or b"")
    return "802.11g" if any((rate & 0x7F) in _OFDM_RATES for rate in rates) else "802.11b"


# --- Security -------------------------------------------------------------------------


def security(elements: Elements, *, privacy: bool) -> str:
    """Name the security a network uses, in the same terms on every platform."""
    rsn = _rsn(elements.get(RSN))
    wpa = _wpa(elements.vendor(MICROSOFT_OUI, WPA_OUI_TYPE))
    if rsn is not None:
        akms, capabilities = rsn
        if akms & _SUITE_B_192_AKMS:
            return "WPA3 Enterprise"
        if akms & _ENTERPRISE_AKMS:
            # WPA3-Enterprise only mode: SHA-256 802.1X with management frame protection required.
            wpa3 = _AKM_8021X_SHA256 in akms and _AKM_8021X not in akms and capabilities & _MFP_REQUIRED
            return "WPA3 Enterprise" if wpa3 else "WPA2 Enterprise"
        if akms & _SAE_AKMS:
            return "WPA2/WPA3" if akms & _PSK_AKMS else "WPA3"
        if akms & _PSK_AKMS:
            return "WPA/WPA2" if wpa else "WPA2"
        if _OWE_AKM in akms:
            return "OWE"
        return "Unknown"
    if wpa is not None:
        return "WPA Enterprise" if _AKM_8021X in wpa else "WPA"
    return "WEP" if privacy else "Open"


def _suites(body: bytes, offset: int, oui: bytes) -> tuple[set[int] | None, int]:
    """Types of the ``oui`` suites in a count-prefixed suite list, and the offset just past it.

    The set is None when the element ends before the list starts.
    """
    if len(body) < offset + 2:
        return None, offset
    count = int.from_bytes(body[offset : offset + 2], "little")
    start, end = offset + 2, min(len(body), offset + 2 + 4 * count)
    kinds = {body[i + 3] for i in range(start, end - 3, 4) if body[i : i + 3] == oui}
    return kinds, offset + 2 + 4 * count


def _rsn(body: bytes | None) -> tuple[set[int], int] | None:
    """AKM suite types and RSN Capabilities of an RSN element (9.4.2.24)."""
    if body is None or len(body) < 2:
        return None
    # Version (2), Group Data Cipher Suite (4), then the pairwise cipher and AKM suite lists.
    _, offset = _suites(body, 6, IEEE_OUI)
    akms, offset = _suites(body, offset, IEEE_OUI)
    capabilities = int.from_bytes(body[offset : offset + 2], "little") if len(body) >= offset + 2 else 0
    # A missing AKM list means 802.1X.
    return (akms if akms is not None else {_AKM_8021X}), capabilities


def _wpa(body: bytes | None) -> set[int] | None:
    """AKM types of a WPA element, which uses RSN's layout with Microsoft's OUI."""
    if body is None or len(body) < 2:
        return None
    _, offset = _suites(body, 6, MICROSOFT_OUI)
    akms, _ = _suites(body, offset, MICROSOFT_OUI)
    return akms if akms is not None else {_AKM_8021X}


# --- Country --------------------------------------------------------------------------


def country(elements: Elements) -> str | None:
    """The ISO 3166 country code from the Country element (9.4.2.8)."""
    body = elements.get(COUNTRY)
    if body is None or len(body) < 2:
        return None
    code = body[:2].decode("ascii", errors="replace").upper()
    # "XX" is a placeholder some access points send when no country is configured.
    return code if code.isascii() and code.isalpha() and code != "XX" else None
