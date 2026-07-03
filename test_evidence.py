"""P1/P2 — cột bằng chứng DoH, TCP, Playwright error."""

from live.evidence import LayerEvidence, format_doh_cell
from live.labels import format_dns_column


def test_format_doh_cell_noerror():
    text = format_doh_cell("NOERROR", ["1.1.1.1", "2606:4700::1"])
    assert text.startswith("NOERROR:")
    assert "1.1.1.1" in text


def test_layer_evidence_row_kw():
    ev = LayerEvidence(
        google_doh_rcode="NOERROR",
        google_doh_ips=["8.8.8.8"],
        cloudflare_doh_rcode="TIMEOUT",
        cloudflare_doh_ips=[],
        tcp_80="OK 8.8.8.8:80",
        tcp_443="FAIL",
        playwright_error="Navigation timeout",
    )
    row = ev.as_row_kw()
    assert "TCP 80" in row
    assert row["TCP 80"] == "OK 8.8.8.8:80"
    assert row["TCP 443"] == "FAIL"
    assert "timeout" in row["Playwright error"].lower()
    assert "Google DoH" not in row


def test_format_dns_column_empty():
    assert format_dns_column("NXDOMAIN", []) == "NXDOMAIN: (không có A/AAAA)"
