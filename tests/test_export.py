import csv
import io
import json
from dataclasses import replace
from datetime import datetime

import pytest

from factories import make_network
from wifianalyzer.analysis import recommend
from wifianalyzer.export import CSV_COLUMNS, ScanFileError, from_json, to_csv, to_json
from wifianalyzer.models import Band, ScanResult


def saved(result, **changes):
    """``result`` as Save Scan writes it, with top-level keys replaced."""
    data = json.loads(to_json(result, [recommend(result, Band.GHZ_5)]))
    data.update(changes)
    return data


def with_network(result, **changes):
    data = saved(result)
    data["networks"][0].update(changes)
    return json.dumps(data)


def test_saved_scans_open_as_they_were(sample_result):
    result = replace(sample_result, networks=[replace(sample_result.networks[0], ssid="Café", bssid="aa:bb")])
    assert from_json(to_json(result, [])) == result


def test_values_with_defaults_may_be_left_out(sample_result):
    data = saved(sample_result)
    del data["country"]
    for network in data["networks"]:
        del network["beacon_interval"], network["is_current"]
    result = from_json(json.dumps(data))
    assert result.country is None
    assert not any(n.is_current for n in result.networks)


def test_times_without_an_offset_are_taken_as_local(sample_result):
    result = from_json(json.dumps(saved(sample_result, timestamp="2026-10-30T09:15:00")))
    assert result.timestamp.utcoffset() is not None
    assert result.timestamp.replace(tzinfo=None) == datetime(2026, 10, 30, 9, 15)  # noqa: DTZ001


def test_bytes_are_read_as_utf8(sample_result):
    assert from_json(to_json(sample_result, []).encode()) == sample_result


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("not json", "isn't valid JSON"),
        (b"\xff\xfe\x00", "isn't valid JSON"),
        ("[]", "the file isn't a JSON object"),
        ('{"interface": "en0"}', '"networks" is missing'),
    ],
)
def test_files_that_arent_scans_are_refused(text, reason):
    with pytest.raises(ScanFileError, match=reason):
        from_json(text)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"rssi": "-50"}, '"rssi" has the wrong type'),
        ({"rssi": True}, '"rssi" has the wrong type'),
        ({"rssi": 10**400}, '"rssi" is out of range'),
        ({"noise": 5}, '"noise" is out of range'),
        ({"width": 0}, '"width" isn\'t a channel width'),
        ({"channel": 999}, '"channel" is out of range'),
        ({"band": "60"}, '"band" isn\'t 2.4, 5 or 6'),
        ({"is_current": 1}, '"is_current" has the wrong type'),
    ],
)
def test_networks_the_app_couldnt_draw_are_refused(sample_result, changes, reason):
    with pytest.raises(ScanFileError, match=reason):
        from_json(with_network(sample_result, **changes))


@pytest.mark.parametrize("rate", [float("nan"), float("inf"), 10**400, "866", None])
def test_connections_need_a_real_rate(sample_result, rate):
    data = saved(sample_result)
    data["connection"]["tx_rate"] = rate
    with pytest.raises(ScanFileError, match='"tx_rate"'):
        from_json(json.dumps(data))


def test_bad_timestamps_are_refused(sample_result):
    with pytest.raises(ScanFileError, match='"timestamp"'):
        from_json(json.dumps(saved(sample_result, timestamp="yesterday")))


def rows(result):
    return list(csv.reader(io.StringIO(to_csv(result), newline="")))


def test_csv_lists_every_network_by_band_strongest_first(sample_result):
    header, *body = rows(sample_result)
    assert tuple(header) == CSV_COLUMNS
    assert len(body) == len(sample_result.networks)
    assert [r[1] for r in body] == sorted((r[1] for r in body), key=["2.4 GHz", "5 GHz", "6 GHz"].index)
    five = [r for r in body if r[1] == "5 GHz"]
    assert [r[2] for r in five] == ["1", "2", "3", "4", "5"]
    assert [int(r[5]) for r in five] == sorted((int(r[5]) for r in five), reverse=True)
    current = dict(zip(header, five[0], strict=True))
    assert current["Connected"] == "yes"
    assert current["Channels"] == "36–48"
    assert current["Signal (dBm)"] == "-55"  # numbers stay numbers
    assert current["Noise (dBm)"] == current["Network"] == current["BSSID"] == ""
    assert to_csv(sample_result).endswith("\r\n")


@pytest.mark.parametrize(
    ("ssid", "cell"),
    [
        ('=HYPERLINK("x","y")', '\'=HYPERLINK("x","y")'),
        ("+1", "'+1"),
        ("-net", "'-net"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("cafe\x1b[2J", "cafe\\x1b[2J"),
        ("Home, 2nd floor", "Home, 2nd floor"),
    ],
)
def test_csv_never_hands_spreadsheets_a_formula(ssid, cell):
    result = ScanResult("en0", [make_network(6, -60, ssid=ssid, bssid="aa:bb:cc:dd:ee:ff")], None)
    assert rows(result)[1][3] == cell
