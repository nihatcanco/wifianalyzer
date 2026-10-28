from __future__ import annotations

import pytest

from factories import make_connection, make_network
from wifianalyzer.models import Band, ScanResult


@pytest.fixture
def sample_result() -> ScanResult:
    """A busy 2.4 GHz band and a 5 GHz band where the user is on 36–48 at 80 MHz."""
    networks = [
        make_network(1, -50),
        make_network(1, -72),
        make_network(6, -80),
        make_network(9, -65),
        make_network(11, -70, width=40),
        make_network(36, -55, Band.GHZ_5, 80, is_current=True),
        make_network(36, -56, Band.GHZ_5, 80),  # the same AP's guest SSID
        make_network(44, -78, Band.GHZ_5, 80),
        make_network(100, -85, Band.GHZ_5, 160),
        make_network(149, -60, Band.GHZ_5, 80),
        make_network(37, -70, Band.GHZ_6, 160),
    ]
    return ScanResult(interface="en0", networks=networks, connection=make_connection(36, -55))
