from live.constants import COL_DNS, COL_DNS_LOCAL, COL_DNS_PUBLIC
from live.labels import (
    dns_evidence_columns_dict,
    preserve_dns_evidence_columns,
    primary_dns_display,
    primary_dns_display_from_row,
)


def test_primary_dns_display_prefers_local_real_ips():
    text = primary_dns_display(
        "NOERROR",
        ["1.2.3.4"],
        public_rcode="NOERROR",
        public_ips=["5.6.7.8"],
    )
    assert text == "NOERROR: 1.2.3.4"


def test_primary_dns_display_falls_back_to_public():
    text = primary_dns_display(
        "NXDOMAIN",
        [],
        public_rcode="NOERROR",
        public_ips=["5.6.7.8"],
    )
    assert text == "NOERROR: 5.6.7.8"


def test_dns_evidence_columns_dict_single_column():
    out = dns_evidence_columns_dict(
        "NOERROR",
        ["1.1.1.1"],
        public_rcode="NOERROR",
        public_ips=["1.1.1.1"],
    )
    assert list(out.keys()) == [COL_DNS]
    assert "1.1.1.1" in out[COL_DNS]


def test_preserve_dns_evidence_columns_legacy_and_new():
    prior = {COL_DNS: "NOERROR: 1.1.1.1", COL_DNS_LOCAL: "NOERROR: 1.1.1.1"}
    new = {COL_DNS: "—", "Status": "Timeout"}
    merged = preserve_dns_evidence_columns(new, prior)
    assert merged[COL_DNS] == "NOERROR: 1.1.1.1"


def test_primary_dns_display_from_row_legacy_csv():
    row = {
        COL_DNS_LOCAL: "NOERROR: 9.9.9.9",
        COL_DNS_PUBLIC: "NOERROR: 9.9.9.9",
    }
    assert primary_dns_display_from_row(row) == "NOERROR: 9.9.9.9"
