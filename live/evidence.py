"""Cột bằng chứng theo tầng (P1/P2 — OONI-style)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import COL_PLAYWRIGHT_ERR, COL_TCP_443, COL_TCP_80


def format_doh_cell(rcode: str, ips: list[str]) -> str:
    from .labels import format_dns_column

    rc = (rcode or "").strip()
    if not rc or rc == "—":
        return "—"
    return format_dns_column(rc, ips)


@dataclass
class LayerEvidence:
    google_doh_rcode: str = "—"
    google_doh_ips: list[str] = field(default_factory=list)
    cloudflare_doh_rcode: str = "—"
    cloudflare_doh_ips: list[str] = field(default_factory=list)
    tcp_80: str = "—"
    tcp_443: str = "—"
    playwright_error: str = ""

    def as_row_kw(self) -> dict[str, str]:
        return {
            COL_TCP_80: self.tcp_80 or "—",
            COL_TCP_443: self.tcp_443 or "—",
            COL_PLAYWRIGHT_ERR: (self.playwright_error or "").strip() or "—",
        }
