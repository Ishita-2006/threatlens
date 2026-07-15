# backend/app/services/scan_service.py
import asyncio
import ipaddress
import logging
import socket

from sqlalchemy.orm import Session

from .. import models
from .network_scanner import check_dns_records, scan_ports
from .web_scanner import analyze_security_headers, check_exposed_files, check_http_to_https

logger = logging.getLogger("threatlens")

RISKY_PORTS = {
    21: ("FTP", "Medium"),
    23: ("Telnet", "High"),
    3306: ("MySQL", "High"),
    3389: ("RDP", "High"),
    5432: ("PostgreSQL", "High"),
}


class InvalidTargetError(ValueError):
    """Raised when a submitted domain is malformed, or resolves to a
    private/loopback/link-local address."""


def validate_target(domain: str) -> None:
    """Rejects malformed input and, importantly, rejects domains that
    resolve to non-public IP ranges.

    Why this matters: this service makes live TCP connections and HTTP
    requests to whatever hostname a client supplies. Without this check, a
    client could point it at "localhost", an internal hostname, or a
    domain deliberately configured to resolve to an internal IP (e.g.
    10.x.x.x, 169.254.x.x) and use this API to port-scan or probe your own
    internal network -- a classic SSRF pattern. This is a standard
    safeguard for any service that fetches user-supplied hosts, not
    optional hardening.
    """
    domain = domain.strip().strip(".")
    if not domain or len(domain) > 253:
        raise InvalidTargetError("Domain is empty or too long.")

    try:
        resolved_ip = socket.gethostbyname(domain)
    except socket.gaierror as exc:
        raise InvalidTargetError(f"Could not resolve '{domain}': {exc}") from exc

    ip = ipaddress.ip_address(resolved_ip)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        raise InvalidTargetError(
            f"'{domain}' resolves to a non-public address ({resolved_ip}); "
            "this scanner only targets public internet hosts."
        )


def _get_or_create_target(db: Session, domain: str) -> models.Target:
    target = db.query(models.Target).filter(models.Target.domain_or_ip == domain).first()
    if target is None:
        target = models.Target(domain_or_ip=domain)
        db.add(target)
        db.commit()
        db.refresh(target)
    return target


def _evaluate_ports(open_ports):
    vulns = []
    deductions = 0
    for entry in open_ports:
        port = entry["port"]
        if port in RISKY_PORTS:
            service_name, severity = RISKY_PORTS[port]
            deductions += 15 if severity == "High" else 10
            vulns.append({
                "type": f"Exposed {service_name} Port",
                "severity": severity,
                "description": f"Port {port} ({service_name}) is open and reachable from the public internet.",
                "evidence": f"TCP connection succeeded on port {port}.",
                "remediation": f"Restrict access to port {port} via firewall rules, VPN, or disable the service if unused.",
            })
    return vulns, deductions


def _evaluate_dns(dns_records: dict):
    """Only flags a vulnerability when a record is definitively "Missing".
    A value of "Unknown (DNS query failed)" means we couldn't determine the
    answer -- that's not the same as the record being absent, and must not
    be reported as a finding."""
    vulns = []
    deductions = 0
    if dns_records.get("SPF") == "Missing":
        deductions += 10
        vulns.append({
            "type": "Missing SPF Record",
            "severity": "Medium",
            "description": "No SPF record was found, making it easier for attackers to spoof emails from this domain.",
            "evidence": "No TXT record starting with 'v=spf1' found.",
            "remediation": "Publish an SPF TXT record specifying authorized mail servers.",
        })
    if dns_records.get("DMARC") == "Missing":
        deductions += 10
        vulns.append({
            "type": "Missing DMARC Record",
            "severity": "Medium",
            "description": "No DMARC record was found, reducing protection against email spoofing and phishing.",
            "evidence": "No TXT record starting with 'v=DMARC1' found at _dmarc subdomain.",
            "remediation": "Publish a DMARC TXT record with at least a monitoring (p=none) policy to start.",
        })
    return vulns, deductions


async def run_scan(domain: str, db: Session) -> models.Scan:
    """Runs the full passive scan pipeline and persists the result.

    This is the single source of truth for "what a scan does" -- called by
    the API layer. Keeping it out of the route handler means it can be
    reused (e.g. by a background worker/queue later) without touching the
    HTTP layer, and can be tested without spinning up FastAPI at all.
    """
    target = _get_or_create_target(db, domain)

    scan = models.Scan(target_id=target.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        (
            open_ports,
            dns_records,
            https_enforced,
            (header_vulns, header_deductions),
            (file_vulns, file_deductions),
        ) = await asyncio.gather(
            scan_ports(domain),
            check_dns_records(domain),
            check_http_to_https(domain),
            analyze_security_headers(domain),
            check_exposed_files(domain),
        )

        deductions = header_deductions + file_deductions
        detected_vulns = list(header_vulns) + list(file_vulns)

        if not https_enforced:
            deductions += 10
            detected_vulns.append({
                "type": "Missing HTTPS Redirect",
                "severity": "Medium",
                "description": "The server does not force HTTP traffic to HTTPS, allowing potential plain-text interception.",
                "evidence": "HTTP request did not end on an https:// URL after following redirects.",
                "remediation": "Configure the web server to return a 301 redirect for all port 80 traffic.",
            })

        port_vulns, port_deductions = _evaluate_ports(open_ports)
        detected_vulns.extend(port_vulns)
        deductions += port_deductions

        dns_vulns, dns_deductions = _evaluate_dns(dns_records)
        detected_vulns.extend(dns_vulns)
        deductions += dns_deductions

        overall_score = max(0, 100 - deductions)

        for v in detected_vulns:
            db.add(models.Vulnerability(
                scan_id=scan.id,
                vulnerability_type=v["type"],
                severity=v["severity"],
                description=v["description"],
                evidence=v["evidence"],
                remediation=v["remediation"],
            ))

        scan.status = "completed"
        scan.overall_score = overall_score
        scan.open_ports = open_ports
        scan.dns_records = dns_records
        scan.https_enforced = https_enforced
        db.commit()
        db.refresh(scan)

        logger.info("Scan %s for %s completed with score %s", scan.id, domain, overall_score)
        return scan

    except Exception:
        db.rollback()
        scan.status = "failed"
        db.commit()
        logger.exception("Scan failed for domain %s", domain)
        raise