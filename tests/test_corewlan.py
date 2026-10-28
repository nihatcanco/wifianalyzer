import contextlib
import re
import sys
import types

import pytest

from factories import make_connection, make_network
from wifianalyzer.models import Band
from wifianalyzer.scanner import ScanError, mark_current
from wifianalyzer.scanner.corewlan import CoreWLANScanner, security_from_flags


@pytest.mark.parametrize(
    ("flags", "label"),
    [
        # Flag sets observed from real access points on macOS 27.
        ({3, 4, 5, 13}, "WPA2"),
        ({2, 3, 4, 5, 13}, "WPA/WPA2"),
        ({3, 4, 5, 11, 13}, "WPA2/WPA3"),
        ({11, 13}, "WPA3"),
        ({8, 9, 10}, "WPA2 Enterprise"),
        ({0}, "Open"),
        ({1}, "WEP"),
        (set(), "Unknown"),
    ],
)
def test_security_from_flags(flags, label):
    assert security_from_flags(flags) == label


def test_mark_current_by_bssid():
    networks = [
        make_network(36, -50, Band.GHZ_5, 80, bssid="aa:aa:aa:aa:aa:01"),
        make_network(36, -60, Band.GHZ_5, 80, bssid="aa:aa:aa:aa:aa:02"),
    ]
    connection = make_connection(36, -50, bssid="aa:aa:aa:aa:aa:02")
    assert [n.is_current for n in mark_current(networks, connection)] == [False, True]


def test_mark_current_without_bssid_uses_closest_rssi_on_same_channel():
    networks = [
        make_network(36, -80, Band.GHZ_5, 80),
        make_network(36, -58, Band.GHZ_5, 80),
        make_network(52, -57, Band.GHZ_5, 80),
    ]
    marked = mark_current(networks, make_connection(36, -57))
    assert [n.is_current for n in marked] == [False, True, False]


def test_mark_current_when_disconnected():
    networks = [make_network(1, -50)]
    assert mark_current(networks, None) == networks


# --- The scanner, on a stand-in for CoreWLAN ---------------------------------------------


class Channel:
    def __init__(self, number, band, width):
        self.number, self.band, self.width = number, band, width

    def channelNumber(self):
        return self.number

    def channelBand(self):
        return self.band

    def channelWidth(self):
        return self.width


class ScannedNetwork:
    def __init__(self, ssid, rssi, channel, security, phy, noise=0):
        self._ssid, self._rssi, self._channel = ssid, rssi, channel
        self._security, self._phy, self._noise = security, phy, noise

    def ssid(self):
        return self._ssid

    def bssid(self):
        return None  # withheld without Location access

    def rssiValue(self):
        return self._rssi

    def noiseMeasurement(self):
        return self._noise

    def wlanChannel(self):
        return self._channel

    def beaconInterval(self):
        return 100

    def supportsSecurity_(self, mode):
        return mode in self._security

    def supportsPHYMode_(self, mode):
        return mode in self._phy


class Interface:
    powered = True
    error = None

    def __init__(self):
        self.networks = [
            ScannedNetwork(None, -52, Channel(36, 2, 3), {3, 4, 5, 11, 13}, {6}, noise=-91),
            ScannedNetwork(None, -70, Channel(6, 1, 1), {0}, {4}),
            ScannedNetwork(None, -80, None, {0}, {4}),  # no channel: skipped
            ScannedNetwork(None, -75, Channel(37, 3, 4), {11}, {6}),
        ]

    def interfaceName(self):
        return "en0"

    def powerOn(self):
        return self.powered

    def scanForNetworksWithName_includeHidden_error_(self, name, hidden, error):
        if self.error:
            return None, types.SimpleNamespace(localizedDescription=lambda: self.error)
        return self.networks, None

    def wlanChannel(self):
        return Channel(36, 2, 3)

    def rssiValue(self):
        return -51

    def ssid(self):
        return None

    def bssid(self):
        return None

    def noiseMeasurement(self):
        return -92

    def transmitRate(self):
        return 1200.0

    def security(self):
        return 11

    def activePHYMode(self):
        return 6

    def countryCode(self):
        return "TR"


@pytest.fixture
def interface(monkeypatch):
    found = Interface()

    class Client:
        @staticmethod
        def sharedWiFiClient():
            return Client()

        def interface(self):
            return found

        def interfaceWithName_(self, name):
            return found if name == "en0" else None

    monkeypatch.setitem(sys.modules, "CoreWLAN", types.SimpleNamespace(CWWiFiClient=Client))
    monkeypatch.setitem(sys.modules, "objc", types.SimpleNamespace(autorelease_pool=contextlib.nullcontext))
    return found


def test_scan(interface):
    result = CoreWLANScanner().scan()
    assert (result.interface, result.country) == ("en0", "TR")
    current, cafe, six = result.networks
    assert (current.band, current.channel, current.width, current.security, current.phy) == (
        Band.GHZ_5,
        36,
        80,
        "WPA2/WPA3",
        "802.11ax",
    )
    assert current.is_current  # matched by channel and signal, since BSSIDs are withheld
    assert (current.noise, cafe.noise) == (-91, None)
    assert (cafe.band, cafe.width, cafe.security, cafe.phy) == (Band.GHZ_2_4, 20, "Open", "802.11n")
    assert (six.band, six.width) == (Band.GHZ_6, 160)
    conn = result.connection
    assert (conn.rssi, conn.noise, conn.tx_rate, conn.security, conn.phy) == (-51, -92, 1200.0, "WPA3", "802.11ax")


def test_scan_failures(interface):
    scanner = CoreWLANScanner("en0")
    interface.error = "The operation couldn't be completed."
    with pytest.raises(ScanError, match=re.escape("Scan failed: The operation couldn't be completed.")):
        scanner.scan()
    interface.powered = False
    with pytest.raises(ScanError, match="Wi-Fi is turned off on en0"):
        scanner.scan()


def test_unknown_interface(interface):
    with pytest.raises(ScanError, match="No Wi-Fi interface named 'en9'"):
        CoreWLANScanner("en9")
