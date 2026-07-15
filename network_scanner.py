# backend/app/services/network_scanner.py
import asyncio
import logging
import socket
from typing import Dict, List

import dns.exception
import dns.resolver

logger = logging.getLogger("threatlens")

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL"
}

PUBLIC_FALLBACK_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


async def check_single_port(host: str, port: int, timeout: int = 2) -> Dict:
    """Attempts a non-blocking TCP connection to a specific port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "open"}
    except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
        return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "status": "closed"}


async def scan_ports(host: str) -> List[Dict]:
    """Scans multiple ports concurrently."""
    tasks = [check_single_port(host, port) for port in COMMON_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    return [res for res in results if res["status"] == "open"]


def _txt_rdata_to_string(rdata) -> str:
    """Reconstructs the full TXT record value.

    BUG FIX (parsing): a TXT record's value can be split across multiple
    <character-string> segments (each up to 255 bytes) at the DNS
    wire-protocol level -- SPF records with several 'include:' mechanisms
    commonly exceed 255 bytes and get split this way. dnspython's
    rdata.to_text() renders each segment in its own quotes for zone-file
    display, e.g. '"v=spf1 include:_spf.example.com " "~all"'. The old code
    did `.to_text().strip('"')`, which only strips the outer quotes and
    leaves a stray `" "` sitting in the middle of the reconstructed value.
    Per RFC 7208 / RFC 1035 the segments must be concatenated with NO
    separator to get the real value, so we read the raw byte segments
    directly instead of parsing the display text.
    """
    return b"".join(rdata.strings).decode("utf-8", errors="replace")


def _resolve_txt(name: str, timeout: float = 6.0):
    """Resolves TXT records.

    BUG FIX (false positives / root cause): domains with many TXT records
    (site-verification tokens, DKIM selectors, SPF, etc. -- instagram.com
    has ~10) produce a combined answer too big for a plain (non-EDNS) UDP
    DNS packet. That forces a fallback to TCP DNS, and TCP port 53 is
    commonly blocked by firewalls/corporate networks/containers that
    otherwise allow plain UDP DNS -- causing the whole query to time out
    even though the record exists. This was the actual cause of the false
    "missing SPF" report on instagram.com (confirmed by reproducing it:
    DMARC, a single small record, succeeded instantly; the full TXT set
    timed out until EDNS0 was enabled).

    Requesting a larger UDP payload via EDNS0 lets the full answer arrive
    in one UDP packet, avoiding the TCP fallback entirely -- this fixes the
    root cause rather than working around it. A public-resolver fallback is
    kept as a second line of defense for genuinely broken local resolvers.
    """
    resolver_attempts = [dns.resolver.Resolver()]
    fallback = dns.resolver.Resolver(configure=False)
    fallback.nameservers = PUBLIC_FALLBACK_NAMESERVERS
    resolver_attempts.append(fallback)

    last_exc: Exception = dns.exception.Timeout()
    for resolver in resolver_attempts:
        resolver.lifetime = timeout
        resolver.use_edns(0, ednsflags=0, payload=4096)
        try:
            return resolver.resolve(name, "TXT")
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            last_exc = exc
            continue
    raise last_exc


def _check_dns_records_sync(domain: str) -> Dict[str, str]:
    """Passively queries public DNS records for security misconfigurations.

    BUG FIX (false positives): "Missing" is now only reported when the DNS
    answer definitively contains no such record (NXDOMAIN / NoAnswer). A
    failed query (timeout, unreachable resolver, etc.) is reported as
    "Unknown (DNS query failed)" instead, so a network hiccup during the
    scan is never mistaken for "this domain has no SPF record" -- this was
    the actual cause of false "missing SPF" reports on domains (like
    google.com) that do publish one.
    """
    records = {"SPF": "Missing", "DMARC": "Missing"}

    try:
        txt_answers = _resolve_txt(domain)
        for rdata in txt_answers:
            txt_record = _txt_rdata_to_string(rdata)
            if txt_record.lower().startswith("v=spf1"):
                records["SPF"] = txt_record
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass  # domain definitively has no TXT records / doesn't exist -> genuinely Missing
    except Exception as exc:  # noqa: BLE001 - the query failed, that's not the same as "absent"
        records["SPF"] = "Unknown (DNS query failed)"
        logger.warning("SPF lookup failed for %s: %s", domain, exc)

    try:
        dmarc_answers = _resolve_txt(f"_dmarc.{domain}")
        for rdata in dmarc_answers:
            txt_record = _txt_rdata_to_string(rdata)
            if txt_record.lower().startswith("v=dmarc1"):
                records["DMARC"] = txt_record
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as exc:  # noqa: BLE001
        records["DMARC"] = "Unknown (DNS query failed)"
        logger.warning("DMARC lookup failed for %s: %s", domain, exc)

    return records


async def check_dns_records(domain: str) -> Dict[str, str]:
    """Runs the blocking DNS lookups in a worker thread so they don't stall
    the event loop while other scan tasks run concurrently."""
    return await asyncio.to_thread(_check_dns_records_sync, domain)