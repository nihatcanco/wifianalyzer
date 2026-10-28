import pytest

from wifianalyzer.channels import (
    CHANNELS,
    block_label,
    bonded_center,
    candidate_channels,
    channel_frequency,
    from_frequency,
    is_dfs,
    overlap,
    span,
)
from wifianalyzer.models import Band


@pytest.mark.parametrize(
    ("band", "channel", "mhz"),
    [
        (Band.GHZ_2_4, 1, 2412),
        (Band.GHZ_2_4, 13, 2472),
        (Band.GHZ_2_4, 14, 2484),
        (Band.GHZ_5, 36, 5180),
        (Band.GHZ_5, 165, 5825),
        (Band.GHZ_6, 1, 5955),
        (Band.GHZ_6, 2, 5935),
        (Band.GHZ_6, 233, 7115),
    ],
)
def test_channel_frequency(band, channel, mhz):
    assert channel_frequency(band, channel) == mhz


@pytest.mark.parametrize(
    ("band", "channel", "width", "center"),
    [
        (Band.GHZ_5, 36, 20, 36),
        (Band.GHZ_5, 44, 40, 46),
        (Band.GHZ_5, 44, 80, 42),
        (Band.GHZ_5, 56, 160, 50),
        (Band.GHZ_5, 124, 160, 114),
        (Band.GHZ_5, 161, 80, 155),
        (Band.GHZ_2_4, 1, 40, 3),
        (Band.GHZ_2_4, 11, 40, 9),
        (Band.GHZ_6, 5, 40, 3),
        (Band.GHZ_6, 37, 160, 47),
        (Band.GHZ_6, 1, 320, 31),
    ],
)
def test_bonded_center(band, channel, width, center):
    assert bonded_center(band, channel, width) == center


def test_non_overlapping_24ghz_channels():
    one, six, eleven = (span(Band.GHZ_2_4, c, 20) for c in (1, 6, 11))
    assert overlap(one, six) == 0
    assert overlap(six, eleven) == 0
    assert overlap(one, span(Band.GHZ_2_4, 3, 20)) == 10


def test_bonded_span_covers_block():
    assert span(Band.GHZ_5, 44, 80) == (5170, 5250)
    assert span(Band.GHZ_5, 52, 80) == (5250, 5330)
    assert block_label(Band.GHZ_5, 44, 80) == "36–48"
    assert block_label(Band.GHZ_5, 52, 80) == "52–64"
    assert block_label(Band.GHZ_5, 64, 160) == "36–64"
    assert block_label(Band.GHZ_2_4, 6, 40) == "6"


@pytest.mark.parametrize(
    ("channel", "width", "expected"),
    [(36, 20, False), (36, 80, False), (36, 160, True), (52, 20, True), (144, 20, True), (149, 80, False)],
)
def test_dfs(channel, width, expected):
    assert is_dfs(Band.GHZ_5, channel, width) is expected


def test_dfs_only_applies_to_5ghz():
    assert not is_dfs(Band.GHZ_2_4, 6)
    assert not is_dfs(Band.GHZ_6, 53)


def test_candidates():
    assert candidate_channels(Band.GHZ_2_4, 40) == [1, 6, 11]
    assert candidate_channels(Band.GHZ_5, 80) == [36, 52, 100, 116, 132, 149]
    assert candidate_channels(Band.GHZ_5, 160) == [36, 100]
    assert candidate_channels(Band.GHZ_5, 20)[-1] == 165
    assert candidate_channels(Band.GHZ_6, 160) == [1, 33, 65, 97, 129, 161, 193]
    assert len(candidate_channels(Band.GHZ_6, 20)) == 59


@pytest.mark.parametrize(
    ("mhz", "located"),
    [
        (2412, (Band.GHZ_2_4, 1)),
        (2472, (Band.GHZ_2_4, 13)),
        (2484, (Band.GHZ_2_4, 14)),
        (5180, (Band.GHZ_5, 36)),
        (5885, (Band.GHZ_5, 177)),
        (5935, (Band.GHZ_6, 2)),
        (5955, (Band.GHZ_6, 1)),
        (7115, (Band.GHZ_6, 233)),
        (4920, None),  # Japan's 4.9 GHz band
        (60480, None),
    ],
)
def test_from_frequency(mhz, located):
    assert from_frequency(mhz) == located


@pytest.mark.parametrize("band", list(Band))
def test_frequencies_round_trip(band):
    for channel in CHANNELS[band]:
        assert from_frequency(channel_frequency(band, channel)) == (band, channel)
