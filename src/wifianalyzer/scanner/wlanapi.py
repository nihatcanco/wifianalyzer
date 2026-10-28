"""Scanning on Windows through the Native Wifi API (wlanapi.dll).

The structures are declared with fixed-width integer types rather than ``ctypes.wintypes``,
whose DWORD is 8 bytes outside Windows. That keeps their layout the same on every platform,
so the parsing can be tested anywhere.

Since Windows 11 24H2, these functions fail with ERROR_ACCESS_DENIED unless the user lets
desktop apps use their location, because nearby networks reveal where a computer is.
"""

from __future__ import annotations

import ctypes
import logging
import threading
from collections.abc import Callable
from ctypes import POINTER, Structure, byref, c_int32, c_size_t, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from ..channels import from_frequency
from ..models import Band, Connection, Network, ScanResult
from . import elements
from .base import AccessDeniedError, ScanError, Scanner, common_country, format_mac, mark_current

log = logging.getLogger(__name__)

DWORD = c_uint32
ULONG = c_uint32
LONG = c_int32
USHORT = c_uint16
UCHAR = c_uint8
BOOL = c_int32
HANDLE = c_void_p

_WLAN_MAX_NAME_LENGTH = 256
_DOT11_SSID_MAX_LENGTH = 32
_DOT11_RATE_SET_MAX_LENGTH = 126

ERROR_ACCESS_DENIED = 5
ERROR_NOT_FOUND = 1168
ERROR_SERVICE_NOT_ACTIVE = 1062
ERROR_INVALID_STATE = 5023

_CLIENT_VERSION = 2  # Windows Vista and later
_BSS_TYPE_INFRASTRUCTURE = 1
_INTERFACE_STATE_CONNECTED = 1
_OPCODE_RADIO_STATE = 4  # WLAN_INTF_OPCODE values
_OPCODE_CURRENT_CONNECTION = 7
_OPCODE_CHANNEL_NUMBER = 8
_OPCODE_RSSI = 0x10000102
_RADIO_ON = 1
_NOTIFICATION_SOURCE_ACM = 0x08
_ACM_SCAN_COMPLETE = 7
_ACM_SCAN_FAIL = 8
_CAPABILITY_PRIVACY = 0x0010

# Drivers must finish a scan within four seconds. Without notifications, wait that long.
SCAN_TIMEOUT = 6.0
_DRIVER_SCAN_TIME = 4.0

# DOT11_PHY_TYPE and DOT11_AUTH_ALGORITHM values.
_PHY_TYPES = {4: "802.11a", 5: "802.11b", 6: "802.11g", 7: "802.11n", 8: "802.11ac", 10: "802.11ax", 11: "802.11be"}
_AUTH_ALGORITHMS = {
    1: "Open",
    2: "WEP",
    3: "WPA Enterprise",
    4: "WPA",
    6: "WPA2 Enterprise",
    7: "WPA2",
    8: "WPA3 Enterprise",
    9: "WPA3",
    10: "OWE",
    11: "WPA3 Enterprise",
}


class GUID(Structure):
    _fields_ = (("Data1", c_uint32), ("Data2", c_uint16), ("Data3", c_uint16), ("Data4", c_uint8 * 8))

    def __str__(self) -> str:
        tail = bytes(self.Data4).hex().upper()
        return f"{{{self.Data1:08X}-{self.Data2:04X}-{self.Data3:04X}-{tail[:4]}-{tail[4:]}}}"


class DOT11_SSID(Structure):
    _fields_ = (("uSSIDLength", ULONG), ("ucSSID", UCHAR * _DOT11_SSID_MAX_LENGTH))

    def raw(self) -> bytes:
        return bytes(self.ucSSID)[: min(self.uSSIDLength, _DOT11_SSID_MAX_LENGTH)]


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = (
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", USHORT * _WLAN_MAX_NAME_LENGTH),  # WCHAR, 2 bytes on Windows
        ("isState", DWORD),
    )


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = (("dwNumberOfItems", DWORD), ("dwIndex", DWORD), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1))


class WLAN_RATE_SET(Structure):
    _fields_ = (("uRateSetLength", ULONG), ("usRateSet", USHORT * _DOT11_RATE_SET_MAX_LENGTH))


class WLAN_BSS_ENTRY(Structure):
    _fields_ = (
        ("dot11Ssid", DOT11_SSID),
        ("uPhyId", ULONG),
        ("dot11Bssid", UCHAR * 6),
        ("dot11BssType", DWORD),
        ("dot11BssPhyType", DWORD),
        ("lRssi", LONG),
        ("uLinkQuality", ULONG),
        ("bInRegDomain", UCHAR),
        ("usBeaconPeriod", USHORT),
        ("ullTimestamp", c_uint64),
        ("ullHostTimestamp", c_uint64),
        ("usCapabilityInformation", USHORT),
        ("ulChCenterFrequency", ULONG),  # kHz
        ("wlanRateSet", WLAN_RATE_SET),
        ("ulIeOffset", ULONG),  # from the start of this entry
        ("ulIeSize", ULONG),
    )


class WLAN_BSS_LIST(Structure):
    _fields_ = (("dwTotalSize", DWORD), ("dwNumberOfItems", DWORD), ("wlanBssEntries", WLAN_BSS_ENTRY * 1))


class WLAN_ASSOCIATION_ATTRIBUTES(Structure):
    _fields_ = (
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", DWORD),
        ("dot11Bssid", UCHAR * 6),
        ("dot11PhyType", DWORD),
        ("uDot11PhyIndex", ULONG),
        ("wlanSignalQuality", ULONG),  # 0 to 100, linear from -100 to -50 dBm
        ("ulRxRate", ULONG),  # kb/s
        ("ulTxRate", ULONG),
    )


class WLAN_SECURITY_ATTRIBUTES(Structure):
    _fields_ = (
        ("bSecurityEnabled", BOOL),
        ("bOneXEnabled", BOOL),
        ("dot11AuthAlgorithm", DWORD),
        ("dot11CipherAlgorithm", DWORD),
    )


class WLAN_CONNECTION_ATTRIBUTES(Structure):
    _fields_ = (
        ("isState", DWORD),
        ("wlanConnectionMode", DWORD),
        ("strProfileName", USHORT * _WLAN_MAX_NAME_LENGTH),
        ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
        ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES),
    )


class WLAN_PHY_RADIO_STATE(Structure):
    _fields_ = (("dwPhyIndex", DWORD), ("dot11SoftwareRadioState", DWORD), ("dot11HardwareRadioState", DWORD))


class WLAN_RADIO_STATE(Structure):
    _fields_ = (("dwNumberOfPhys", DWORD), ("PhyRadioState", WLAN_PHY_RADIO_STATE * 64))


class WLAN_NOTIFICATION_DATA(Structure):
    _fields_ = (
        ("NotificationSource", DWORD),
        ("NotificationCode", DWORD),
        ("InterfaceGuid", GUID),
        ("dwDataSize", DWORD),
        ("pData", c_void_p),
    )


# Windows calls back with the stdcall convention; CFUNCTYPE stands in elsewhere so this imports.
_FUNCTYPE = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
NOTIFICATION_CALLBACK = _FUNCTYPE(None, POINTER(WLAN_NOTIFICATION_DATA), c_void_p)

_C = TypeVar("_C", bound="Structure | c_int32 | c_uint32")


# --- Reading the API's buffers --------------------------------------------------------


@dataclass(frozen=True)
class Interface:
    guid: bytes
    description: str
    connected: bool


@dataclass(frozen=True)
class BssEntry:
    ssid: bytes
    bssid: str
    phy_type: int
    rssi: int
    beacon_period: int
    capability: int
    frequency: int  # MHz
    ies: bytes


def _wide_string(chars: Any) -> str:
    return bytes(chars).decode("utf-16-le", errors="replace").split("\0", 1)[0]


def read_interfaces(address: int) -> list[Interface]:
    """The interfaces in a WLAN_INTERFACE_INFO_LIST."""
    header = WLAN_INTERFACE_INFO_LIST.from_address(address)
    items = (WLAN_INTERFACE_INFO * header.dwNumberOfItems).from_address(
        address + WLAN_INTERFACE_INFO_LIST.InterfaceInfo.offset
    )
    return [
        Interface(
            guid=bytes(item.InterfaceGuid),
            description=_wide_string(item.strInterfaceDescription),
            connected=item.isState == _INTERFACE_STATE_CONNECTED,
        )
        for item in items
    ]


def read_bss_list(address: int) -> list[BssEntry]:
    """The entries of a WLAN_BSS_LIST, each with its information elements.

    Offsets come from the driver, so each read is checked against the list's total size.
    """
    header = WLAN_BSS_LIST.from_address(address)
    end = address + header.dwTotalSize
    first = address + WLAN_BSS_LIST.wlanBssEntries.offset
    size = ctypes.sizeof(WLAN_BSS_ENTRY)
    entries = []
    for i in range(header.dwNumberOfItems):
        at = first + i * size
        if at + size > end:
            break
        entry = WLAN_BSS_ENTRY.from_address(at)
        if entry.dot11BssType != _BSS_TYPE_INFRASTRUCTURE:
            continue
        ies_at = at + entry.ulIeOffset
        ies = ctypes.string_at(ies_at, entry.ulIeSize) if entry.ulIeSize and ies_at + entry.ulIeSize <= end else b""
        entries.append(
            BssEntry(
                ssid=entry.dot11Ssid.raw(),
                bssid=format_mac(bytes(entry.dot11Bssid)),
                phy_type=entry.dot11BssPhyType,
                rssi=entry.lRssi,
                beacon_period=entry.usBeaconPeriod,
                capability=entry.usCapabilityInformation,
                frequency=entry.ulChCenterFrequency // 1000,
                ies=ies,
            )
        )
    return entries


def network(entry: BssEntry) -> Network | None:
    located = from_frequency(entry.frequency)
    if located is None:
        return None
    band, channel = located
    advertised = elements.parse(entry.ies, band, privacy=bool(entry.capability & _CAPABILITY_PRIVACY))
    return Network(
        ssid=elements.decode_ssid(entry.ssid),
        bssid=entry.bssid,
        rssi=entry.rssi,
        noise=None,  # Windows doesn't report noise
        band=band,
        channel=channel,
        width=advertised.width,
        security=advertised.security,
        phy=advertised.phy if entry.ies else _PHY_TYPES.get(entry.phy_type, "unknown"),
        beacon_interval=entry.beacon_period or None,
    )


# --- The API --------------------------------------------------------------------------


class WlanError(OSError):
    """A wlanapi.dll function returned an error code."""

    def __init__(self, code: int, function: str) -> None:
        format_error = getattr(ctypes, "FormatError", None)
        super().__init__(code, format_error(code).strip() if format_error else f"error {code}")
        self.code = code
        self.function = function

    def __str__(self) -> str:
        return f"{self.function} failed: {self.strerror} ({self.code})"


def _check(code: int, function: str) -> None:
    if code != 0:
        raise WlanError(code, function)


class WlanApi:
    """The parts of wlanapi.dll the scanner uses, on one client handle."""

    def __init__(self) -> None:
        try:
            dll = ctypes.WinDLL("wlanapi.dll")  # type: ignore[attr-defined,unused-ignore]
        except (AttributeError, OSError) as e:
            raise ScanError("Wi-Fi isn't available: Windows' Native Wifi API (wlanapi.dll) is missing") from e
        self._dll = dll
        for name, argtypes in {
            "WlanOpenHandle": (DWORD, c_void_p, POINTER(DWORD), POINTER(HANDLE)),
            "WlanCloseHandle": (HANDLE, c_void_p),
            "WlanEnumInterfaces": (HANDLE, c_void_p, POINTER(c_void_p)),
            "WlanScan": (HANDLE, POINTER(GUID), c_void_p, c_void_p, c_void_p),
            "WlanGetNetworkBssList": (HANDLE, POINTER(GUID), c_void_p, DWORD, BOOL, c_void_p, POINTER(c_void_p)),
            "WlanQueryInterface": (HANDLE, POINTER(GUID), DWORD, c_void_p, POINTER(DWORD), POINTER(c_void_p), c_void_p),
            "WlanRegisterNotification": (HANDLE, DWORD, BOOL, NOTIFICATION_CALLBACK, c_void_p, c_void_p, c_void_p),
        }.items():
            function = getattr(dll, name)
            function.argtypes, function.restype = argtypes, DWORD
        dll.WlanFreeMemory.argtypes, dll.WlanFreeMemory.restype = (c_void_p,), None

        negotiated, handle = DWORD(), HANDLE()
        _check(dll.WlanOpenHandle(_CLIENT_VERSION, None, byref(negotiated), byref(handle)), "WlanOpenHandle")
        self._handle = handle
        self._callback: Any = None  # Windows keeps calling it until the handle is closed

    def close(self) -> None:
        if self._handle:
            self._dll.WlanCloseHandle(self._handle, None)
            self._handle = HANDLE()

    def _owned(self, fill: Callable[[c_void_p], int], function: str) -> c_void_p:
        """Call a function that allocates its result, which must be freed with WlanFreeMemory."""
        pointer = c_void_p()
        _check(fill(pointer), function)
        return pointer

    def interfaces(self) -> list[Interface]:
        pointer = self._owned(
            lambda p: self._dll.WlanEnumInterfaces(self._handle, None, byref(p)), "WlanEnumInterfaces"
        )
        try:
            return read_interfaces(pointer.value or 0)
        finally:
            self._dll.WlanFreeMemory(pointer)

    def scan(self, guid: bytes) -> None:
        _check(self._dll.WlanScan(self._handle, byref(GUID.from_buffer_copy(guid)), None, None, None), "WlanScan")

    def bss_list(self, guid: bytes, ssid: bytes | None = None, *, secured: bool = False) -> list[BssEntry]:
        """The driver's cached scan results, optionally only those for one network name."""
        filter_ssid = None
        if ssid is not None:
            filter_ssid = DOT11_SSID(len(ssid), (UCHAR * _DOT11_SSID_MAX_LENGTH)(*ssid))
        pointer = self._owned(
            lambda p: self._dll.WlanGetNetworkBssList(
                self._handle,
                byref(GUID.from_buffer_copy(guid)),
                byref(filter_ssid) if filter_ssid is not None else None,
                _BSS_TYPE_INFRASTRUCTURE,
                secured,
                None,
                byref(p),
            ),
            "WlanGetNetworkBssList",
        )
        try:
            return read_bss_list(pointer.value or 0)
        finally:
            self._dll.WlanFreeMemory(pointer)

    def query(self, guid: bytes, opcode: int, kind: type[_C]) -> _C:
        """A copy of an interface property."""
        size = DWORD()
        pointer = self._owned(
            lambda p: self._dll.WlanQueryInterface(
                self._handle, byref(GUID.from_buffer_copy(guid)), opcode, None, byref(size), byref(p), None
            ),
            "WlanQueryInterface",
        )
        try:
            if size.value < ctypes.sizeof(kind):
                raise WlanError(ERROR_INVALID_STATE, "WlanQueryInterface")
            return cast(_C, kind.from_buffer_copy(ctypes.string_at(pointer.value or 0, ctypes.sizeof(kind))))
        finally:
            self._dll.WlanFreeMemory(pointer)

    def on_scan_finished(self, guid: bytes, handler: Callable[[], None]) -> None:
        """Call ``handler`` (on a Windows thread) whenever a scan on the interface completes or fails."""

        def notify(data: Any, _context: Any) -> None:
            n = data.contents
            if (
                n.NotificationSource == _NOTIFICATION_SOURCE_ACM
                and n.NotificationCode in (_ACM_SCAN_COMPLETE, _ACM_SCAN_FAIL)
                and bytes(n.InterfaceGuid) == guid
            ):
                handler()

        self._callback = NOTIFICATION_CALLBACK(notify)
        _check(
            self._dll.WlanRegisterNotification(
                self._handle, _NOTIFICATION_SOURCE_ACM, True, self._callback, None, None, None
            ),
            "WlanRegisterNotification",
        )


def interface_alias(guid: bytes) -> str | None:
    """The name Windows shows for an interface, such as "Wi-Fi", from the IP Helper API."""
    try:
        iphlpapi = ctypes.WinDLL("iphlpapi.dll")  # type: ignore[attr-defined,unused-ignore]
        to_luid = iphlpapi.ConvertInterfaceGuidToLuid
        to_alias = iphlpapi.ConvertInterfaceLuidToAlias
    except (AttributeError, OSError):
        return None
    to_luid.argtypes, to_luid.restype = (POINTER(GUID), POINTER(c_uint64)), DWORD
    to_alias.argtypes, to_alias.restype = (POINTER(c_uint64), ctypes.c_wchar_p, c_size_t), DWORD
    luid = c_uint64()
    alias = ctypes.create_unicode_buffer(257)  # IF_MAX_STRING_SIZE + 1
    if to_luid(byref(GUID.from_buffer_copy(guid)), byref(luid)) or to_alias(byref(luid), alias, len(alias)):
        return None
    return alias.value or None


# --- The scanner ----------------------------------------------------------------------

_LOCATION_HINT = (
    "Windows only shows nearby Wi-Fi networks to apps that may use your location. Turn on Location "
    'services and "Let desktop apps access your location" in Settings › Privacy & security › Location.'
)


def _scan_error(error: WlanError) -> ScanError:
    log.debug("%s", error)
    if error.code == ERROR_ACCESS_DENIED:
        return AccessDeniedError(_LOCATION_HINT)
    if error.code == ERROR_SERVICE_NOT_ACTIVE:
        return ScanError("No Wi-Fi interface found: the WLAN AutoConfig service isn't running")
    return ScanError(f"Scan failed: {error.strerror}")


class WlanApiScanner(Scanner):
    def __init__(
        self,
        interface: str | None = None,
        *,
        api: Callable[[], WlanApi] = WlanApi,
        alias: Callable[[bytes], str | None] = interface_alias,
    ) -> None:
        try:
            self._api = api()
        except WlanError as e:
            raise _scan_error(e) from None
        try:
            available = self._api.interfaces()
            names = {i.guid: alias(i.guid) or i.description for i in available}
            chosen = _choose(available, names, interface)
        except WlanError as e:
            self._api.close()
            raise _scan_error(e) from None
        except ScanError:
            self._api.close()
            raise
        self._guid = chosen.guid
        self.name = names[chosen.guid]
        self._finished = threading.Event()
        try:
            self._api.on_scan_finished(self._guid, self._finished.set)
            self._wait = SCAN_TIMEOUT
        except WlanError as e:
            log.warning("Scan notifications are unavailable, so each scan waits %.0f s: %s", _DRIVER_SCAN_TIME, e)
            self._wait = _DRIVER_SCAN_TIME

    def close(self) -> None:
        self._api.close()

    def cancel(self) -> None:
        self._finished.set()

    def scan(self) -> ScanResult:
        self._finished.clear()
        try:
            self._api.scan(self._guid)
        except WlanError as e:
            if not self._radio_on():
                raise ScanError(f"Wi-Fi is turned off on {self.name}") from None
            raise _scan_error(e) from None
        if not self._finished.wait(self._wait):
            log.debug("The scan didn't report back within %.0f s; using the results so far", self._wait)
        try:
            entries = self._api.bss_list(self._guid)
            connection = self._connection(entries)
        except WlanError as e:
            raise _scan_error(e) from None
        networks = [n for n in map(network, entries) if n is not None]
        current = next((e for e in entries if connection and e.bssid == connection.bssid), None)
        return ScanResult(
            interface=self.name,
            networks=mark_current(networks, connection),
            connection=connection,
            country=common_country(
                (elements.country(elements.Elements(e.ies)) for e in entries),
                preferred=elements.country(elements.Elements(current.ies)) if current else None,
            ),
        )

    def connection(self) -> Connection | None:
        try:
            return self._connection()
        except WlanError as e:
            raise _scan_error(e) from None

    def _connection(self, entries: list[BssEntry] | None = None) -> Connection | None:
        try:
            attributes = self._api.query(self._guid, _OPCODE_CURRENT_CONNECTION, WLAN_CONNECTION_ATTRIBUTES)
        except WlanError as e:
            if e.code in (ERROR_INVALID_STATE, ERROR_NOT_FOUND):  # not connected
                return None
            raise
        if attributes.isState != _INTERFACE_STATE_CONNECTED:
            return None
        link = attributes.wlanAssociationAttributes
        security = attributes.wlanSecurityAttributes
        bssid = format_mac(bytes(link.dot11Bssid))
        ssid = link.dot11Ssid.raw()
        if entries is None:
            entries = self._api.bss_list(self._guid, ssid, secured=bool(security.bSecurityEnabled))
        entry = next((e for e in entries if e.bssid == bssid), None)
        try:
            rssi = self._api.query(self._guid, _OPCODE_RSSI, LONG).value
        except WlanError:
            rssi = -100 + link.wlanSignalQuality // 2  # the documented mapping of signal quality
        located = from_frequency(entry.frequency) if entry else None
        if entry and located:
            band, channel = located
            advertised = elements.parse(entry.ies, band, privacy=bool(entry.capability & _CAPABILITY_PRIVACY))
            width, label, phy = advertised.width, advertised.security, advertised.phy
        else:
            # Not in the cached results (yet): the channel number alone can't tell 6 GHz apart.
            channel = self._api.query(self._guid, _OPCODE_CHANNEL_NUMBER, ULONG).value
            band = Band.GHZ_2_4 if channel <= 14 else Band.GHZ_5
            width, label, phy = 20, _AUTH_ALGORITHMS.get(security.dot11AuthAlgorithm, "Unknown"), "unknown"
        return Connection(
            ssid=elements.decode_ssid(ssid),
            bssid=bssid,
            rssi=rssi,
            noise=None,
            tx_rate=link.ulTxRate / 1000,
            band=band,
            channel=channel,
            width=width,
            security=label,
            phy=_PHY_TYPES.get(link.dot11PhyType, phy),
        )

    def _radio_on(self) -> bool:
        try:
            state = self._api.query(self._guid, _OPCODE_RADIO_STATE, WLAN_RADIO_STATE)
        except WlanError:
            return True  # unknown; report the original error instead
        phys = state.PhyRadioState[: min(state.dwNumberOfPhys, len(state.PhyRadioState))]
        return any(p.dot11SoftwareRadioState == _RADIO_ON and p.dot11HardwareRadioState == _RADIO_ON for p in phys)


def _choose(available: list[Interface], names: dict[bytes, str], wanted: str | None) -> Interface:
    if not available:
        raise ScanError("No Wi-Fi interface found")
    if wanted is None:
        return next((i for i in available if i.connected), available[0])
    key = wanted.strip().strip("{}").casefold()
    for i in available:
        guid = str(GUID.from_buffer_copy(i.guid)).strip("{}").casefold()
        if key in (names[i.guid].casefold(), i.description.casefold(), guid):
            return i
    choices = ", ".join(names[i.guid] for i in available)
    raise ScanError(f"No Wi-Fi interface named {wanted!r}. Available: {choices}")
