import asyncio
import dns.asyncresolver

async def test():
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 3
    resolver.lifetime = 3
    try:
        answer = await resolver.resolve("fxbrokers.io", "HTTPS")
        for rdata in answer:
            params = getattr(rdata, "params", {})
            print(f"params: {params}")
            print(f"ECH key 5: {5 in params if params else False}")
    except Exception as e:
        print(f"FAIL: {e}")

asyncio.run(test())