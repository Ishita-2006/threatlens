# backend/app/services/web_scanner.py
from typing import Dict, List, Tuple

import httpx


async def check_http_to_https(domain: str) -> bool:
    """Checks whether HTTP traffic eventually ends up on HTTPS.

    BUG FIX: the previous version only inspected the *first* redirect's
    Location header. Many real sites -- google.com included -- redirect
    http://domain -> http://www.domain (still plain HTTP) before the actual
    http -> https hop happens on the *second* redirect. Checking only hop
    one reports "not enforced" even though HTTPS is enforced by the time the
    chain finishes. Now we follow the whole chain and check where it ends.
    """
    url = f"http://{domain}"
    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            was_redirected = len(response.history) > 0
            ended_on_https = response.url.scheme == "https"
            return was_redirected and ended_on_https
        except (httpx.TooManyRedirects, httpx.RequestError):
            return False


async def analyze_security_headers(domain: str) -> Tuple[List[Dict], int]:
    """Analyzes HTTP response headers for missing security controls.

    BUG FIX: the previous version fetched https://domain without following
    redirects. If that URL itself returns a 301/302 (e.g. https://google.com
    -> https://www.google.com), the code was reading the *redirect
    response's* headers -- which commonly omit HSTS/CSP/etc. -- instead of
    the real page's headers. That's what caused false "Missing HSTS" /
    "Missing Clickjacking Protection" reports on sites that do set these
    headers on their actual page. Now we follow to the final response, and
    check headers across the *whole* chain (redirect hops + final page)
    since some sites set a given header on one hop but not the other.
    """
    url = f"https://{domain}"
    vulns = []
    deductions = 0

    async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
        try:
            response = await client.get(url)
            all_responses = list(response.history) + [response]

            headers: Dict[str, str] = {}
            cookie_headers: List[str] = []
            for r in all_responses:
                for k, v in r.headers.items():
                    headers.setdefault(k.lower(), v)
                cookie_headers.extend(r.headers.get_list("set-cookie"))

            # 1. Clickjacking Protection (X-Frame-Options or CSP)
            if "x-frame-options" not in headers and "content-security-policy" not in headers:
                deductions += 15
                vulns.append({
                    "type": "Missing Clickjacking Protection",
                    "severity": "High",
                    "description": "The site does not implement X-Frame-Options or a Content-Security-Policy with frame-ancestors. This allows attackers to embed the site in an iframe to trick users into clicking malicious links.",
                    "evidence": "Headers missing: X-Frame-Options, Content-Security-Policy",
                    "remediation": "Implement the 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
                })

            # 2. Strict-Transport-Security (HSTS)
            if "strict-transport-security" not in headers:
                deductions += 10
                vulns.append({
                    "type": "Missing HSTS Header",
                    "severity": "Medium",
                    "description": "HTTP Strict Transport Security (HSTS) is not enforced, leaving users vulnerable to man-in-the-middle downgrade attacks.",
                    "evidence": "Header missing: Strict-Transport-Security",
                    "remediation": "Implement the HSTS header with a strong max-age directive."
                })

            # 3. Insecure Cookies (every Set-Cookie header across the whole chain)
            insecure_cookies = [
                c for c in cookie_headers
                if "secure" not in c.lower() or "httponly" not in c.lower()
            ]
            if insecure_cookies:
                deductions += 10
                vulns.append({
                    "type": "Insecure Cookie Configuration",
                    "severity": "Medium",
                    "description": f"{len(insecure_cookies)} of {len(cookie_headers)} cookie(s) are missing the Secure or HttpOnly flag.",
                    "evidence": f"Set-Cookie header: {insecure_cookies[0][:50]}...",
                    "remediation": "Ensure all session cookies include the 'Secure' and 'HttpOnly' flags to prevent XSS theft and transit interception."
                })

        except httpx.RequestError:
            pass  # Target might not be serving HTTPS web traffic

    return vulns, deductions


async def check_exposed_files(domain: str) -> Tuple[List[Dict], int]:
    """Non-intrusive check for common information disclosure paths."""
    vulns = []
    deductions = 0
    paths_to_check = {
        "/.env": "Exposed Environment Variables",
        "/admin/": "Exposed Admin Panel",
        "/backup.zip": "Public Backup File"
    }

    async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
        for path, vuln_name in paths_to_check.items():
            try:
                response = await client.get(f"https://{domain}{path}")
                if response.status_code == 200:
                    deductions += 25
                    vulns.append({
                        "type": vuln_name,
                        "severity": "Critical",
                        "description": f"Sensitive file or directory ({path}) is publicly accessible.",
                        "evidence": f"HTTP 200 OK on {path}",
                        "remediation": "Restrict access to this path immediately using web server configuration or authentication."
                    })
            except httpx.RequestError:
                continue

    return vulns, deductions