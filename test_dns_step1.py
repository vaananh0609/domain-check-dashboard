"""Bước 1 DNS — evaluate_dns_step1 và sinkhole (không TIMEOUT)."""

from live.dns import (
    evaluate_dns_step1,
    isp_dns_blocks_resolution,
    real_ips_from_list,
)

_CF = ["104.21.67.232", "172.67.182.124"]
_JUNK = ["127.0.0.1"]


def test_dead_both_nxdomain():
    d = evaluate_dns_step1("NXDOMAIN", [], "NXDOMAIN", [])
    assert d.outcome == "dead"
    assert d.probe_ips == []


def test_dead_both_timeout():
    d = evaluate_dns_step1("TIMEOUT", [], "TIMEOUT", [])
    assert d.outcome == "dead"
    assert d.probe_ips == []


def test_dead_both_dns_error():
    d = evaluate_dns_step1("DNS_ERROR", [], "DNS_ERROR", [])
    assert d.outcome == "dead"
    assert d.probe_ips == []


def test_dead_timeout_and_dns_error():
    d = evaluate_dns_step1("TIMEOUT", [], "DNS_ERROR", [])
    assert d.outcome == "dead"
    assert d.probe_ips == []


def test_continue_one_nxdomain_one_timeout():
    d = evaluate_dns_step1("NXDOMAIN", [], "TIMEOUT", [])
    assert d.outcome == "continue"
    assert d.probe_ips == []


def test_continue_both_noerror_empty():
    d = evaluate_dns_step1("NOERROR", [], "NOERROR", [])
    assert d.outcome == "continue"


def test_blocked_local_nxdomain_public_real():
    d = evaluate_dns_step1("NXDOMAIN", [], "NOERROR", _CF)
    assert d.outcome == "blocked"
    assert isp_dns_blocks_resolution([], _CF, local_rcode="NXDOMAIN") is True


def test_blocked_local_junk_public_real():
    d = evaluate_dns_step1("NOERROR", _JUNK, "NOERROR", _CF)
    assert d.outcome == "blocked"
    assert isp_dns_blocks_resolution(_JUNK, _CF) is True


def test_suspicion_local_timeout_public_real():
    d = evaluate_dns_step1("TIMEOUT", [], "NOERROR", _CF)
    assert d.outcome == "continue"
    assert d.dns_suspicion is True
    assert d.probe_ips == real_ips_from_list(_CF)
    assert "Nghi vấn" in d.dns_column_suffix
    assert isp_dns_blocks_resolution([], _CF, local_rcode="TIMEOUT") is False


def test_suspicion_local_dns_error_public_real():
    d = evaluate_dns_step1("DNS_ERROR", [], "NOERROR", _CF)
    assert d.outcome == "continue"
    assert d.dns_suspicion is True


def test_continue_both_have_ips():
    local = ["2606:4700:3032::ac43:b67c"]
    d = evaluate_dns_step1("NOERROR", local, "NOERROR", _CF)
    assert d.outcome == "continue"
    assert not d.dns_suspicion
    assert d.probe_ips == local


def test_prefer_ipv4_in_probe_ips():
    d = evaluate_dns_step1("TIMEOUT", [], "NOERROR", _CF)
    assert d.probe_ips[0] == "104.21.67.232"
