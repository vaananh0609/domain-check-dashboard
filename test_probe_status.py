"""Phân loại TIMEOUT khi probe thất bại (chưa chốt Blocked)."""

from live.classify import _status_for_probe_failure
from live.constants import STATUS_TIMEOUT
from live.tls_probe import TlsProbeResult


def test_probe_failure_tls_timeout_is_timeout():
    tls = TlsProbeResult(
        version="FAIL",
        negotiated="",
        error="handshake timeout",
        failure_kind="timeout",
    )
    assert _status_for_probe_failure(tls_result=tls) == STATUS_TIMEOUT


def test_probe_failure_sni_reset_is_timeout():
    tls = TlsProbeResult(
        version="FAIL",
        negotiated="",
        error="reset",
        failure_kind="sni_reset",
    )
    assert _status_for_probe_failure(tls_result=tls) == STATUS_TIMEOUT


def test_probe_failure_connection_closed_is_timeout():
    assert _status_for_probe_failure(fail_text="net::ERR_CONNECTION_CLOSED") == STATUS_TIMEOUT


def test_probe_failure_playwright_timeout_text():
    assert _status_for_probe_failure(fail_text="Navigation timeout of 30000 ms exceeded") == STATUS_TIMEOUT


def test_probe_failure_waf_suspected_is_timeout():
    assert _status_for_probe_failure(waf_suspected=True) == STATUS_TIMEOUT


def test_probe_failure_ssl_error_without_isp_is_timeout():
    tls = TlsProbeResult(
        version="FAIL",
        negotiated="",
        error="SSL",
        failure_kind="ssl_error",
    )
    assert _status_for_probe_failure(tls_result=tls, fail_text="SSL Error") == STATUS_TIMEOUT
