import random

import pytest

from beacons import (
    EHT_CAPABILITIES,
    HE_CAPABILITIES,
    HT_CAPABILITIES,
    MFP_REQUIRED,
    VHT_CAPABILITIES,
    eht_operation,
    he_operation,
    ht_operation,
    ie,
    rsn,
    six_ghz_info,
    vht_operation,
    wpa,
)
from wifianalyzer.models import Band
from wifianalyzer.scanner import elements
from wifianalyzer.scanner.elements import Elements, channel_width, decode_ssid, parse, security, standard

# --- Elements -------------------------------------------------------------------------


def test_elements_are_read_in_order_with_extensions_keyed_by_their_extension_id():
    data = ie(0, b"Cafe") + HE_CAPABILITIES + ie(221, b"\x00\x50\xf2\x04rest")
    found = Elements(data)
    assert found.get(elements.SSID) == b"Cafe"
    assert found.get(elements.HE_CAPABILITIES) == bytes(20)
    assert found.vendor(b"\x00\x50\xf2", 4) == b"rest"
    assert found.vendor(b"\x00\x50\xf2", 1) is None
    assert found.get(elements.RSN) is None


def test_a_truncated_element_keeps_the_ones_before_it():
    data = ie(0, b"Cafe") + bytes([48, 20]) + b"\x01\x00"
    found = Elements(data)
    assert found.get(elements.SSID) == b"Cafe"
    assert found.get(elements.RSN) is None


def test_parsing_never_fails_on_garbage():
    rng = random.Random(80211)
    for _ in range(3000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(80)))
        for band in Band:
            parse(data, band, privacy=rng.random() < 0.5)


# --- Names ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "name"),
    [
        (b"Home", "Home"),
        ("Café ☕".encode(), "Café ☕"),
        (b"", None),
        (b"\0\0\0\0", None),  # hidden networks often send zeros of the real name's length
        (None, None),
        (b"\xff\xfeok", "��ok"),
    ],
)
def test_decode_ssid(raw, name):
    assert decode_ssid(raw) == name


# --- Channel width --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "band", "width"),
    [
        (b"", Band.GHZ_2_4, 20),
        (ht_operation(6, 0b000), Band.GHZ_2_4, 20),
        (ht_operation(1, 0b101), Band.GHZ_2_4, 40),  # secondary above
        (ht_operation(11, 0b111), Band.GHZ_2_4, 40),  # secondary below
        (ht_operation(1, 0b001), Band.GHZ_2_4, 20),  # an offset, but 20 MHz only
        (ht_operation(36, 0b101) + vht_operation(0, 0, 0), Band.GHZ_5, 40),
        (ht_operation(36, 0b101) + vht_operation(1, 42, 0), Band.GHZ_5, 80),
        (ht_operation(36, 0b101) + vht_operation(1, 42, 50), Band.GHZ_5, 160),
        (ht_operation(36, 0b101) + vht_operation(1, 42, 155), Band.GHZ_5, 80),  # 80+80
        (ht_operation(36, 0b101) + vht_operation(2, 50, 0), Band.GHZ_5, 160),  # deprecated encoding
        (ht_operation(36, 0b101) + he_operation(vht=bytes([1, 42, 0])), Band.GHZ_5, 80),
        (he_operation(six_ghz=six_ghz_info(37, 0, 37, 0)), Band.GHZ_6, 20),
        (he_operation(six_ghz=six_ghz_info(37, 1, 35, 0)), Band.GHZ_6, 40),
        (he_operation(six_ghz=six_ghz_info(37, 2, 39, 0)), Band.GHZ_6, 80),
        (he_operation(six_ghz=six_ghz_info(37, 3, 39, 47)), Band.GHZ_6, 160),
        (he_operation(six_ghz=six_ghz_info(37, 3, 47, 0)), Band.GHZ_6, 160),
        (he_operation(six_ghz=six_ghz_info(37, 3, 39, 103)), Band.GHZ_6, 80),  # 80+80
        (he_operation(vht=bytes(3), cohosted=True, six_ghz=six_ghz_info(37, 2, 39, 0)), Band.GHZ_6, 80),
        (he_operation(six_ghz=six_ghz_info(37, 3, 39, 47)) + eht_operation(4, 47, 31), Band.GHZ_6, 320),
        (he_operation(), Band.GHZ_6, 20),
    ],
)
def test_channel_width(data, band, width):
    assert channel_width(Elements(data), band) == width


# --- Wi-Fi standard -------------------------------------------------------------------

DSSS_RATES = ie(1, b"\x82\x84\x8b\x96")
OFDM_RATES = ie(1, b"\x82\x84\x8b\x96\x0c\x12\x18\x24") + ie(50, b"\x30\x48\x60\x6c")


@pytest.mark.parametrize(
    ("data", "band", "phy"),
    [
        (HT_CAPABILITIES + VHT_CAPABILITIES + HE_CAPABILITIES + EHT_CAPABILITIES, Band.GHZ_5, "802.11be"),
        (HT_CAPABILITIES + VHT_CAPABILITIES + HE_CAPABILITIES, Band.GHZ_5, "802.11ax"),
        (HT_CAPABILITIES + HE_CAPABILITIES, Band.GHZ_2_4, "802.11ax"),
        (HT_CAPABILITIES + VHT_CAPABILITIES, Band.GHZ_5, "802.11ac"),
        (HT_CAPABILITIES + VHT_CAPABILITIES, Band.GHZ_2_4, "802.11n"),  # VHT doesn't exist on 2.4 GHz
        (HT_CAPABILITIES, Band.GHZ_5, "802.11n"),
        (b"", Band.GHZ_5, "802.11a"),
        (OFDM_RATES, Band.GHZ_2_4, "802.11g"),
        (DSSS_RATES, Band.GHZ_2_4, "802.11b"),
        (ie(1, b"\x82\x84\xff"), Band.GHZ_2_4, "802.11b"),  # 0xff is the HT membership selector, not a rate
        (b"", Band.GHZ_6, "802.11ax"),
    ],
)
def test_standard(data, band, phy):
    assert standard(Elements(data), band) == phy


# --- Security -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "privacy", "label"),
    [
        (b"", False, "Open"),
        (b"", True, "WEP"),
        (rsn(2), True, "WPA2"),
        (rsn(2, 4, 6), True, "WPA2"),  # PSK with fast roaming and SHA-256 variants
        (rsn(2, 8, capabilities=0x80), True, "WPA2/WPA3"),
        (rsn(8, capabilities=MFP_REQUIRED), True, "WPA3"),
        (rsn(24, capabilities=MFP_REQUIRED), True, "WPA3"),  # SAE with a group-dependent hash
        (rsn(2) + wpa(2), True, "WPA/WPA2"),
        (wpa(2), True, "WPA"),
        (wpa(1), True, "WPA Enterprise"),
        (rsn(1), True, "WPA2 Enterprise"),
        (rsn(1, 3), True, "WPA2 Enterprise"),
        (rsn(5), True, "WPA2 Enterprise"),
        (rsn(5, capabilities=MFP_REQUIRED), True, "WPA3 Enterprise"),
        (rsn(1, 5, capabilities=MFP_REQUIRED), True, "WPA2 Enterprise"),  # transition mode
        (rsn(12, capabilities=MFP_REQUIRED), True, "WPA3 Enterprise"),  # 192-bit
        (rsn(18, capabilities=MFP_REQUIRED), True, "OWE"),
        (rsn(1, oui=b"\x00\x40\x96"), True, "Unknown"),  # only a vendor's own AKM
        (ie(48, b"\x01\x00"), True, "WPA2 Enterprise"),  # no AKM list: 802.1X by default
    ],
)
def test_security(data, privacy, label):
    assert security(Elements(data), privacy=privacy) == label


# --- Country and the whole beacon -----------------------------------------------------


@pytest.mark.parametrize(
    ("body", "code"),
    [(b"DE ", "DE"), (b"us\x04", "US"), (b"XX ", None), (b"\x00\x00 ", None), (b"D", None)],
)
def test_country(body, code):
    assert elements.country(Elements(ie(7, body))) == code


def test_a_typical_wifi6_beacon():
    beacon = (
        ie(0, b"Home")
        + OFDM_RATES
        + ie(3, b"\x24")
        + ie(7, b"US\x20\x24\x04\x17")
        + HT_CAPABILITIES
        + ht_operation(36, 0b101)
        + rsn(2, 8, capabilities=0x80)
        + VHT_CAPABILITIES
        + vht_operation(1, 42, 0)
        + HE_CAPABILITIES
        + he_operation()
        + ie(221, b"\x00\x50\xf2\x02\x01\x01")  # WMM, which must not be mistaken for WPA
    )
    assert parse(beacon, Band.GHZ_5, privacy=True) == elements.Advertised(
        ssid="Home", width=80, phy="802.11ax", security="WPA2/WPA3", country="US"
    )
