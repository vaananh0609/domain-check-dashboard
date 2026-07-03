from live.phase2 import (
    alternate_browser_profile,
    clamp_phase2_timeout_seconds,
    merge_phase2_result,
    phase2_browser_profiles,
    _ips_from_dns_cell,
    _rcode_from_dns_cell,
)
from live.playwright_probe import clamp_browser_timeout_ms


def test_phase2_browser_profiles():
    assert phase2_browser_profiles("edge") == ("chrome", "coccoc")
    assert phase2_browser_profiles("chrome") == ("edge", "coccoc")
    assert phase2_browser_profiles("coccoc") == ("edge", "chrome")


def test_alternate_browser_profile():
    assert alternate_browser_profile("edge") == "chrome"
    assert alternate_browser_profile("chrome") == "edge"
    assert alternate_browser_profile("coccoc") == "edge"


def test_clamp_phase2_timeout():
    assert clamp_phase2_timeout_seconds(60) == 60
    assert clamp_phase2_timeout_seconds(120) == 60
    assert clamp_phase2_timeout_seconds(30) == 60


def test_clamp_browser_phase2_max_60s():
    assert clamp_browser_timeout_ms(60, phase2=True) == 60_000
    assert clamp_browser_timeout_ms(120, phase2=True) == 60_000


def test_parse_dns_cell():
    assert _rcode_from_dns_cell("NOERROR: 1.2.3.4, 4.5.6.7") == "NOERROR"
    assert _ips_from_dns_cell("NOERROR: 1.2.3.4, 4.5.6.7") == ["1.2.3.4", "4.5.6.7"]


def test_preserve_dns_evidence_columns():
    from live.constants import COL_DNS
    from live.labels import preserve_dns_evidence_columns

    prior = {COL_DNS: "NOERROR: 1.1.1.1"}
    new = {COL_DNS: "—", "Status": "Timeout"}
    merged = preserve_dns_evidence_columns(new, prior)
    assert merged[COL_DNS] == prior[COL_DNS]
    assert merged["Status"] == "Timeout"


def test_merge_phase2_keeps_dns():
    from live.constants import COL_DNS

    p1 = {"STT": 1, COL_DNS: "NOERROR: 1.1.1.1", "Status": "Timeout", "Trạng_Thái": "TIMEOUT"}
    p2 = {"Status": "Leaked", "HTTP": "200", "Trạng_Thái": "LEAKED"}
    merged = merge_phase2_result(p1, p2)
    assert merged[COL_DNS] == "NOERROR: 1.1.1.1"
    assert merged["Status"] == "Leaked"
    assert merged["HTTP"] == "200"
