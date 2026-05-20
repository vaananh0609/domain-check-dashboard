import asyncio
import os
import platform
import ssl
import socket
import sys
from typing import Any


def print_header(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def python_environment() -> None:
    print_header("Python / SSL Environment")
    print("python:", sys.executable)
    print("python_version:", platform.python_version())
    print("platform:", platform.platform())
    print("openssl:", ssl.OPENSSL_VERSION)
    print("http_proxy:", os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    print("https_proxy:", os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))
    print("no_proxy:", os.environ.get("NO_PROXY") or os.environ.get("no_proxy"))


# ✅ FIX: chuyển thành async + await getaddrinfo
async def local_dns_lookup(hostname: str, timeout: float = 3.0) -> Any:
    try:
        loop = asyncio.get_running_loop()

        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET),
            timeout=timeout
        )

        ips = sorted({info[4][0] for info in infos if info and len(info) >= 5})

        return {"status": "OK", "ips": ips}

    except Exception as exc:
        return {"status": "FAIL", "error": repr(exc)}


# ✅ FIX: dùng resolve thay vì query
async def public_dns_lookup(hostname: str, nameserver: str, timeout: float = 3.0):
    try:
        import aiodns

        resolver = aiodns.DNSResolver(
            nameservers=[nameserver],
            timeout=timeout,
            tries=1
        )

        # ✅ FIX: support cả version cũ + mới
        if hasattr(resolver, "resolve"):
            answers = await asyncio.wait_for(
                resolver.resolve(hostname, "A"),
                timeout=timeout
            )
        else:
            answers = await asyncio.wait_for(
                resolver.query(hostname, "A"),
                timeout=timeout
            )

        ips = sorted({
            getattr(record, "host", "")
            for record in answers
            if getattr(record, "host", "")
        })

        return {"status": "OK", "nameserver": nameserver, "ips": ips}

    except Exception as exc:
        return {"status": "FAIL", "nameserver": nameserver, "error": repr(exc)}

async def fetch_url(url: str, timeout: float = 5.0) -> Any:
    try:
        try:
            from curl_cffi.requests import AsyncSession
        except ImportError:
            import httpx

            async with httpx.AsyncClient(
                verify=False,
                timeout=timeout,
                follow_redirects=True
            ) as client:
                response = await client.get(url)
                return {
                    "status": "OK",
                    "status_code": response.status_code,
                    "final_url": str(response.url),
                    "tls_version": getattr(response, "http_version", "?"),
                }

        async with AsyncSession() as session:
            response = await session.get(
                url,
                timeout=timeout,
                verify=False,
                impersonate="chrome"
            )

            raw_tls = None
            try:
                ssl_obj = getattr(response, "ssl_object", None)
                if ssl_obj and hasattr(ssl_obj, "version"):
                    raw_tls = ssl_obj.version()
            except Exception:
                pass

            return {
                "status": "OK",
                "status_code": response.status_code,
                "final_url": str(response.url),
                "tls_version": raw_tls or "unknown",
            }

    except Exception as exc:
        return {"status": "FAIL", "error": repr(exc)}


async def run_app_preflight() -> Any:
    try:
        import live.dns as dns

        res = await dns.run_network_preflight(
            ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
            dns_timeout=3,
            timeout=3
        )

        return {"status": "OK", "result": res}

    except Exception as exc:
        return {"status": "FAIL", "error": repr(exc)}


async def main() -> None:
    python_environment()

    print_header("DNS Tests")

    print("local lookup example.com:")
    local_result = await local_dns_lookup("example.com")  # ✅ FIX
    print(local_result)

    print("public lookup example.com via 8.8.8.8:")
    public_1 = await public_dns_lookup("example.com", "8.8.8.8")
    print(public_1)

    print("public lookup example.com via 1.1.1.1:")
    public_2 = await public_dns_lookup("example.com", "1.1.1.1")
    print(public_2)

    print_header("HTTP(S) Tests")

    print("fetch https://example.com:")
    http_result = await fetch_url("https://example.com")
    print(http_result)

    print("fetch https://api.ipify.org:")
    ipify_result = await fetch_url("https://api.ipify.org")
    print(ipify_result)

    print_header("App Preflight (if available)")
    preflight_result = await run_app_preflight()
    print(preflight_result)

    print_header("Summary")
    print("Run the same script on local and server, then compare DNS/IP/HTTP results.")


if __name__ == "__main__":
    asyncio.run(main())