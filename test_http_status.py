"""Tests phân loại HTTP theo RFC 9110."""

from live.http_models import HttpProbeResult, RedirectHop
from live.http_status import (
    KIND_CENSORSHIP_BLOCK,
    KIND_CF_ORIGIN_LEAKED,
    KIND_CLIENT_FORBIDDEN,
    KIND_ISP_REDIRECT_BLOCK,
    KIND_LEAKED,
    KIND_MISDIRECTED,
    KIND_NOT_FOUND_LEAKED,
    KIND_TEMPORARY_ERROR,
    KIND_TOOL_ERROR,
    KIND_WAF_LEAKED,
    analyze_http_context,
    classify_http_status_code,
)


def test_1xx_2xx_leaked():
    assert classify_http_status_code(100) == KIND_LEAKED
    assert classify_http_status_code(200) == KIND_LEAKED
    assert classify_http_status_code(206) == KIND_LEAKED


def test_5xx_leaked_temporary():
    assert classify_http_status_code(500) == KIND_TEMPORARY_ERROR
    assert classify_http_status_code(503) == KIND_TEMPORARY_ERROR
    assert classify_http_status_code(599) == KIND_TEMPORARY_ERROR


def test_cf_520_530_leaked():
    assert classify_http_status_code(522) == KIND_CF_ORIGIN_LEAKED
    assert classify_http_status_code(530) == KIND_CF_ORIGIN_LEAKED


def test_400_tool_error():
    assert classify_http_status_code(400) == KIND_TOOL_ERROR


def test_421_misdirected():
    assert classify_http_status_code(421) == KIND_MISDIRECTED


def test_451_blocked():
    assert classify_http_status_code(451) == KIND_CENSORSHIP_BLOCK


def test_403_cloudflare_waf_leaked():
    assert classify_http_status_code(403, is_cloudflare=True) == KIND_WAF_LEAKED


def test_403_no_cf_forbidden_not_blocked():
    assert classify_http_status_code(403, is_cloudflare=False) == KIND_CLIENT_FORBIDDEN


def test_404_leaked():
    assert classify_http_status_code(404) == KIND_NOT_FOUND_LEAKED
    probe = HttpProbeResult(
        first_status=404,
        final_status=404,
        final_url="https://example.com/missing",
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_NOT_FOUND_LEAKED


def test_403_isp_body_blocked():
    probe = HttpProbeResult(
        first_status=403,
        final_status=403,
        final_url="https://example.com/",
        body="Truy cập bị chặn theo quy định của Bộ Thông tin",
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_CENSORSHIP_BLOCK


def test_403_plain_forbidden_kind():
    probe = HttpProbeResult(
        first_status=403,
        final_status=403,
        final_url="https://example.com/",
        body="Access denied",
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_CLIENT_FORBIDDEN


def test_522_context_leaked():
    probe = HttpProbeResult(
        first_status=522,
        final_status=522,
        final_url="https://example.com/",
        server_header="cloudflare",
        is_cloudflare=True,
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_CF_ORIGIN_LEAKED


def test_status_mapping_404_522_are_leaked():
    from live.classify import _status_for_http_kind

    assert _status_for_http_kind(KIND_NOT_FOUND_LEAKED) == "LEAKED"
    assert _status_for_http_kind(KIND_CF_ORIGIN_LEAKED) == "LEAKED"
    assert _status_for_http_kind(KIND_TEMPORARY_ERROR) == "LEAKED"
    assert _status_for_http_kind(KIND_CENSORSHIP_BLOCK) == "TIMEOUT"
    assert _status_for_http_kind(KIND_ISP_REDIRECT_BLOCK) == "TIMEOUT"


def test_h3_200_wrong_host_misdirected():
    probe = HttpProbeResult(
        first_status=200,
        final_status=200,
        final_url="https://wrong-cdn.example.net/",
        via="curl/h3",
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_MISDIRECTED


def test_h3_200_matching_host_leaked():
    probe = HttpProbeResult(
        first_status=200,
        final_status=200,
        final_url="https://example.com/",
        via="curl/h3",
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_LEAKED


def test_isp_redirect_block():
    probe = HttpProbeResult(
        first_status=302,
        final_status=302,
        final_url="https://block.gateway/warning",
        hops=[
            RedirectHop(
                url="https://example.com",
                status=302,
                location="https://block.gateway/warning",
            )
        ],
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_ISP_REDIRECT_BLOCK


def test_normal_redirect_leaked():
    probe = HttpProbeResult(
        first_status=301,
        final_status=200,
        final_url="https://example.com/",
        hops=[
            RedirectHop(url="http://example.com", status=301, location="https://example.com/"),
            RedirectHop(url="https://example.com/", status=200, location=""),
        ],
    )
    assert analyze_http_context(probe, original_host="example.com") == KIND_LEAKED


def test_http_version_label_trusts_h3_via_over_curl_code():
    from live.http_models import format_curl_http_version

    assert format_curl_http_version(3, "curl/h3") == "h3"
    assert format_curl_http_version(3, "curl/h3-only") == "h3"
    probe = HttpProbeResult(
        first_status=200,
        final_status=200,
        final_url="https://example.com/",
        via="curl/h3",
        http_version_code=3,
    )
    assert probe.http_version_label == "h3"


def test_http_version_tcp_still_maps_h2():
    from live.http_models import format_curl_http_version

    assert format_curl_http_version(3, "curl/https") == "h2"
    assert format_curl_http_version(30, "curl/https") == "h3"


def test_effective_h3_timeout():
    from live.constants import effective_h3_timeout

    assert effective_h3_timeout(10) == 20
    assert effective_h3_timeout(15) == 25
    assert effective_h3_timeout(25) == 30


def test_browser_tls_from_security_details_quic():
    from live.tls_probe import (
        browser_http_ver_from_security,
        format_tls_column,
        tls_result_from_browser_security,
    )

    details = {
        "issuer": "WE1",
        "protocol": "QUIC",
        "subjectName": "himachal.us.com",
        "validFrom": 1778960726,
        "validTo": 1786740177,
    }
    result = tls_result_from_browser_security(details, "himachal.us.com")
    assert result is not None
    assert result.ok
    col = format_tls_column(result)
    assert "OK" in col
    assert "TLS 1.3" in col
    assert "h3" not in col
    assert browser_http_ver_from_security(details) == "h3"


def test_browser_www_hostname_match():
    from live.tls_probe import browser_http_ver_from_security, tls_result_from_browser_security

    result = tls_result_from_browser_security(
        {
            "issuer": "WE1",
            "protocol": "TLS 1.3",
            "subjectName": "15go8.com",
            "validFrom": 1778960726,
            "validTo": 1786740177,
        },
        "www.15go8.com",
    )
    assert result is not None
    assert result.cert_status == "Valid"
    assert browser_http_ver_from_security({"protocol": "TLS 1.3"}) == "h2"
