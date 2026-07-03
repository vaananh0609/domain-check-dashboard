"""Dataclass kết quả HTTP probe (redirect chain, headers)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .constants import REDIRECT_STATUS_CODES


def _via_implies_h3(via: str) -> bool:
    """Transport thực tế khi probe chỉ định HTTP/3 (QUIC)."""
    v = (via or "").lower()
    return any(
        token in v
        for token in ("curl/h3", "curl/h3-", "h3-recheck", "h3only")
    )


def format_curl_http_version(code: int | None, via: str = "") -> str:
    """Map mã CURLINFO_HTTP_VERSION (curl) sang nhãn hiển thị."""
    if _via_implies_h3(via):
        return "h3"
    v = (via or "").lower()
    if "ech" in v:
        base = "h2"
        if code is not None and code > 0:
            labels = {1: "HTTP/1.0", 2: "HTTP/1.1", 3: "h2", 30: "h3"}
            base = labels.get(code, base)
        return f"{base}+ECH"
    if via and "ssl/pin" in via:
        return "HTTP/1.1"
    if code is None or code <= 0:
        return "—"
    labels = {
        1: "HTTP/1.0",
        2: "HTTP/1.1",
        3: "h2",
        30: "h3",
    }
    return labels.get(code, f"HTTP/{code}")


def format_latency_ms(ms: float | None) -> str:
    if ms is None or ms < 0:
        return "—"
    return f"{int(round(ms))}ms"


@dataclass
class RedirectHop:
    url: str
    status: int
    location: str = ""
    server: str = ""


@dataclass
class HttpProbeResult:
    first_status: int
    final_status: int
    final_url: str
    hops: list[RedirectHop] = field(default_factory=list)
    body: str = ""
    server_header: str = ""
    is_cloudflare: bool = False
    redirect_loop: bool = False
    via: str = ""
    http_version_code: int = 0
    latency_ms: float | None = None
    retry_after: str = ""
    http_version_override: str = ""

    @property
    def http_version_label(self) -> str:
        override = (self.http_version_override or "").strip()
        if override:
            return override
        return format_curl_http_version(self.http_version_code, self.via)

    @property
    def latency_label(self) -> str:
        return format_latency_ms(self.latency_ms)

    @property
    def http_display(self) -> str:
        if self.first_status <= 0:
            return "—"
        if self.first_status == self.final_status:
            return str(self.final_status)
        return f"{self.first_status} -> {self.final_status}"

    @property
    def history_urls(self) -> list[str]:
        return [h.url for h in self.hops[:-1]]

    @property
    def chain_display(self) -> str:
        if not self.hops:
            return "—"
        if self.redirect_loop:
            return "REDIRECT LOOP: " + self._compact_hops()
        prefix = f"[{self.via}] " if self.via else ""
        return prefix + self._compact_hops()

    def _compact_hops(self) -> str:
        """Chuỗi redirect dạng url (301) -> url (302) -> final."""
        if not self.hops:
            return "—"
        segments: list[str] = []
        for i, hop in enumerate(self.hops):
            is_last = i == len(self.hops) - 1
            if hop.status in REDIRECT_STATUS_CODES:
                segments.append(f"{hop.url} ({hop.status})")
            elif len(self.hops) == 1:
                segments.append(self.final_url or hop.url)
            elif not is_last:
                segments.append(f"{hop.url} ({hop.status})")
            else:
                if self.final_url and self.final_url != hop.url:
                    segments.append(f"{hop.url} ({hop.status}) -> {self.final_url}")
                elif hop.status > 0:
                    segments.append(f"{self.final_url or hop.url}")
                else:
                    segments.append(self.final_url or hop.url)
        if (
            self.final_url
            and self.hops
            and self.hops[-1].status in REDIRECT_STATUS_CODES
            and (not segments or self.final_url not in segments[-1])
        ):
            segments.append(self.final_url)
        return " -> ".join(segments)

    def _hops_text(self) -> str:
        parts: list[str] = []
        for hop in self.hops:
            loc = f" Location:{hop.location}" if hop.location else ""
            srv = f" Server:{hop.server}" if hop.server else ""
            parts.append(f"{hop.url} -> HTTP {hop.status}{loc}{srv}")
        return " | ".join(parts)

    def to_legacy_tuple(self) -> tuple[int, str, list[str], str, str]:
        """Tương thích code cũ: (final_status, final_url, history_urls, chain, body)."""
        return (
            self.final_status,
            self.final_url,
            self.history_urls,
            self.chain_display,
            self.body,
        )
