import pytest

from factories import make_network
from wifianalyzer import privacy
from wifianalyzer.display import network_name, phy_label, printable
from wifianalyzer.models import Band


@pytest.mark.parametrize(
    ("raw", "shown"),
    [
        ("Home", "Home"),
        ("Café ☕ 5G", "Café ☕ 5G"),
        ("\U0001f468\u200d\U0001f469\u200d\U0001f467 family",) * 2,  # joiners hold emoji together and stay
        ("evil\x1b]0;title\x07", "evil\\x1b]0;title\\x07"),
        ("two\nlines", "two\\nlines"),
        ("txt.\u202eexe", "txt.\\u202eexe"),  # right-to-left override, which disguises names
    ],
)
def test_printable(raw, shown):
    assert printable(raw) == shown


def test_network_name():
    assert network_name(make_network(1, -50, ssid="a\x1bb", bssid="aa:bb:cc:dd:ee:ff")) == "a\\x1bb"
    assert network_name(make_network(1, -50, bssid="aa:bb:cc:dd:ee:ff")) == "(hidden)"
    assert network_name(make_network(1, -50)) == "—"  # withheld by the OS


@pytest.mark.parametrize(
    ("phy", "band", "label"),
    [
        ("802.11ax", Band.GHZ_5, "Wi-Fi 6 (ax)"),
        ("802.11ax", Band.GHZ_6, "Wi-Fi 6E (ax)"),
        ("802.11be", Band.GHZ_6, "Wi-Fi 7 (be)"),
        ("802.11g", Band.GHZ_2_4, "802.11g"),
    ],
)
def test_phy_label(phy, band, label):
    assert phy_label(phy, band) == label


def test_band_formats_as_its_value():
    assert f"{Band.GHZ_5}" == "5"
    assert str(Band.GHZ_2_4) == "2.4"


@pytest.mark.parametrize(
    ("platform", "url"),
    [
        ("darwin", "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"),
        ("win32", "ms-settings:privacy-location"),
        ("linux", None),
    ],
)
def test_settings_url(monkeypatch, platform, url):
    monkeypatch.setattr(privacy.sys, "platform", platform)
    found = privacy.settings_url()
    monkeypatch.undo()
    assert found == url
