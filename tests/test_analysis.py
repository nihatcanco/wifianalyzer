from dataclasses import replace

import pytest

from factories import make_network
from wifianalyzer.analysis import bands_in, recommend, score_channel, signal_label, signal_quality, verdict
from wifianalyzer.models import Band


def test_signal_quality_is_clamped():
    assert signal_quality(-30) == 100
    assert signal_quality(-75) == 50
    assert signal_quality(-110) == 0


def test_signal_label():
    assert [signal_label(r) for r in (-45, -55, -65, -75, -85)] == ["excellent", "good", "fair", "weak", "poor"]


def test_score_counts_full_power_of_co_channel_network():
    score = score_channel([make_network(6, -60)], Band.GHZ_2_4, 6, 20)
    assert score.networks == 1
    assert score.interference_dbm == pytest.approx(-60)


def test_score_scales_partial_overlap():
    # Channel 8 is 10 MHz above 6, so half of its 20 MHz lands in channel 6.
    score = score_channel([make_network(8, -60)], Band.GHZ_2_4, 6, 20)
    assert score.interference_dbm == pytest.approx(-63.01, abs=0.01)


def test_score_of_clear_channel():
    score = score_channel([make_network(1, -40), make_network(36, -40, Band.GHZ_5)], Band.GHZ_2_4, 11, 20)
    assert score.networks == 0
    assert score.interference_dbm is None
    assert score.interference_mw == 0


def test_24ghz_prefers_quietest_of_1_6_11(sample_result):
    report = recommend(sample_result, Band.GHZ_2_4)
    assert report.width == 20
    assert [s.channel for s in report.ranked] == [6, 11, 1]
    assert report.current is None


def test_5ghz_uses_connection_width_and_ignores_own_ap(sample_result):
    report = recommend(sample_result, Band.GHZ_5)
    assert report.width == 80
    assert report.ranked[0].channel == 52  # clear, but DFS
    assert report.ranked[0].interference_dbm is None
    # Only the neighbour on 44 counts against 36–48; the AP itself and its guest SSID don't.
    assert report.current.networks == 1
    assert report.current.interference_dbm == pytest.approx(-78)


def test_clear_non_dfs_channel_beats_clear_dfs_channel(sample_result):
    networks = [n for n in sample_result.networks if n.channel != 149]
    report = recommend(replace(sample_result, networks=networks), Band.GHZ_5)
    assert report.ranked[0].channel == 149
    assert not report.ranked[0].dfs


def test_same_ssid_counts_as_own_network(sample_result):
    connection = replace(sample_result.connection, ssid="home")
    networks = [*sample_result.networks, make_network(100, -50, Band.GHZ_5, 80, ssid="home")]
    report = recommend(replace(sample_result, networks=networks, connection=connection), Band.GHZ_5)
    hundred = next(s for s in report.ranked if s.channel == 100)
    assert hundred.interference_dbm == pytest.approx(-85 - 3.01, abs=0.01)  # only the 160 MHz neighbour


def test_verdicts(sample_result):
    assert verdict(recommend(sample_result, Band.GHZ_5)) == "Switch to 52–64: no neighbours overlap it"
    assert verdict(recommend(sample_result, Band.GHZ_2_4)) == ""  # not connected on 2.4 GHz
    # Without the neighbour on 44, your 36–48 is clear and ranks first (clear and not DFS).
    quiet = replace(sample_result, networks=[n for n in sample_result.networks if n.channel != 44])
    assert verdict(recommend(quiet, Band.GHZ_5)) == "You're already on the best channel"
    # On clear 52–64 (DFS), 36–48 ranks higher, but there's nothing to gain by moving.
    moved = replace(
        quiet,
        connection=replace(quiet.connection, channel=52),
        networks=[replace(n, channel=52) if n.channel == 36 else n for n in quiet.networks],
    )
    assert verdict(recommend(moved, Band.GHZ_5)) == "Your channel is clear, no change needed"


def test_bands_in(sample_result):
    assert bands_in(sample_result) == [Band.GHZ_2_4, Band.GHZ_5, Band.GHZ_6]
