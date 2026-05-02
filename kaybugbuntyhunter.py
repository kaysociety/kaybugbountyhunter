#!/usr/bin/env python3
"""
Kay Bug Bounty Hunter

An authorized, non-destructive recon and web hygiene scanner for bug bounty work.
It performs passive/light active checks and writes TXT, JSON, and HTML reports.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import re
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.request import Request, urlopen


USER_AGENT = "KayBugBountyHunter/1.0 (+authorized-security-research)"
COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "admin",
    "auth",
    "blog",
    "cdn",
    "dev",
    "docs",
    "help",
    "mail",
    "m",
    "portal",
    "shop",
    "staging",
    "static",
    "status",
    "support",
    "test",
    "vpn",
]
COMMON_PORTS = [80, 443, 8080, 8443]
INTERESTING_WORDS = [
    "admin",
    "api",
    "auth",
    "backup",
    "config",
    "dashboard",
    "debug",
    "dev",
    "internal",
    "login",
    "password",
    "private",
    "secret",
    "stage",
    "staging",
    "test",
    "token",
    "upload",
]
SECRET_PATTERNS = {
    "Possible API key": r"(?i)(api[_-]?key|apikey|access[_-]?key)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
    "Possible bearer token": r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}",
    "Possible AWS access key": r"AKIA[0-9A-Z]{16}",
    "Possible private key": r"-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----",
    "Possible password assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
}
TAKEOVER_FINGERPRINTS = [
    "there isn't a github pages site here",
    "nosuchbucket",
    "no such app",
    "the specified bucket does not exist",
    "this shop is unavailable",
    "heroku | no such app",
    "repository not found",
]


@dataclass
class Finding:
    severity: str
    title: str
    target: str
    evidence: str
    recommendation: str


@dataclass
class HostResult:
    host: str
    ips: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    status: dict[str, int] = field(default_factory=dict)
    titles: dict[str, str] = field(default_factory=dict)
    technologies: dict[str, list[str]] = field(default_factory=dict)
    security_headers: dict[str, dict[str, str]] = field(default_factory=dict)
    cookies: dict[str, list[str]] = field(default_factory=dict)
    links: dict[str, list[str]] = field(default_factory=dict)
    forms: dict[str, list[str]] = field(default_factory=dict)
    js_files: dict[str, list[str]] = field(default_factory=dict)
    tls: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def clean_domain(value: str) -> str:
    value = value.strip()
    if "://" in value:
        value = urlparse(value).netloc
    value = value.split("/")[0].split(":")[0].lower().strip(".")
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", value):
        raise ValueError("Target must be a valid domain, for example example.com")
    return value


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def banner() -> None:
    print("=" * 68)
    print("Kay Bug Bounty Hunter - authorized recon and web checks")
    print("=" * 68)
    print("Only scan targets you own or have explicit permission to test.\n")


def http_get(url: str, timeout: float, max_bytes: int = 1024 * 1024) -> tuple[int, dict[str, str], bytes, str]:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"})
    try:
        with urlopen(req, timeout=timeout) as response:
            body = response.read(max_bytes)
            final_url = response.geturl()
            return response.status, dict(response.headers.items()), body, final_url
    except HTTPError as exc:
        body = exc.read(max_bytes)
        return exc.code, dict(exc.headers.items()), body, exc.geturl()
    except (URLError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
        raise RuntimeError(str(exc)) from exc


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({info[4][0] for info in infos})
    except socket.gaierror:
        return []


def tcp_port_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def get_tls_info(host: str, timeout: float) -> dict[str, str]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
                return {
                    "subject": format_cert_name(cert.get("subject", [])),
                    "issuer": format_cert_name(cert.get("issuer", [])),
                    "not_before": cert.get("notBefore", ""),
                    "not_after": cert.get("notAfter", ""),
                    "version": str(cert.get("version", "")),
                }
    except OSError:
        return {}
    except ssl.SSLError as exc:
        return {"error": str(exc)}


def format_cert_name(parts: Iterable[tuple[tuple[str, str], ...]]) -> str:
    flat = []
    for group in parts:
        for key, value in group:
            flat.append(f"{key}={value}")
    return ", ".join(flat)


def extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()[:120]


def extract_attrs(text: str, attr: str) -> list[str]:
    pattern = rf"{attr}\s*=\s*['\"]([^'\"]+)['\"]"
    return sorted(set(html.unescape(m) for m in re.findall(pattern, text, re.I)))


def extract_forms(text: str) -> list[str]:
    forms = []
    for form in re.findall(r"<form\b[^>]*>", text, re.I):
        action = re.search(r"action\s*=\s*['\"]([^'\"]*)['\"]", form, re.I)
        method = re.search(r"method\s*=\s*['\"]([^'\"]*)['\"]", form, re.I)
        forms.append(f"{(method.group(1) if method else 'GET').upper()} {action.group(1) if action else '(current page)'}")
    return sorted(set(forms))


def detect_tech(headers: dict[str, str], text: str) -> list[str]:
    found = []
    server = headers.get("Server") or headers.get("server")
    powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
    if server:
        found.append(f"Server: {server}")
    if powered:
        found.append(f"X-Powered-By: {powered}")
    checks = {
        "WordPress": r"wp-content|wp-includes",
        "React": r"react(?:\.production)?\.min\.js|__REACT_DEVTOOLS_GLOBAL_HOOK__",
        "Angular": r"ng-app|angular(?:\.min)?\.js",
        "Vue": r"vue(?:\.runtime)?(?:\.min)?\.js|data-v-",
        "jQuery": r"jquery(?:-\d+\.\d+\.\d+)?(?:\.min)?\.js",
        "Bootstrap": r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)",
    }
    for name, pattern in checks.items():
        if re.search(pattern, text, re.I):
            found.append(name)
    return sorted(set(found))


def normalize_links(base_url: str, values: Iterable[str], domain: str) -> list[str]:
    output = set()
    for value in values:
        if value.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base_url, value)
        parsed = urlparse(absolute)
        if parsed.scheme in {"http", "https"} and parsed.netloc.endswith(domain):
            output.add(absolute.split("#")[0])
    return sorted(output)


def passive_crtsh(domain: str, timeout: float) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        status, _, body, _ = http_get(url, timeout, max_bytes=2 * 1024 * 1024)
        if status >= 400:
            return []
        records = json.loads(body.decode("utf-8", errors="replace"))
    except (RuntimeError, json.JSONDecodeError):
        return []

    hosts = set()
    for record in records:
        names = str(record.get("name_value", "")).splitlines()
        for name in names:
            name = name.lower().strip().strip("*.").strip(".")
            if name.endswith(domain):
                hosts.add(name)
    return sorted(hosts)


def enumerate_hosts(domain: str, include_passive: bool, timeout: float, threads: int) -> list[str]:
    candidates = {domain, f"www.{domain}"}
    candidates.update(f"{sub}.{domain}" for sub in COMMON_SUBDOMAINS)
    if include_passive:
        print("[*] Querying crt.sh for passive subdomains...")
        candidates.update(passive_crtsh(domain, timeout))

    print(f"[*] Resolving {len(candidates)} candidate hosts...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        results = list(pool.map(lambda host: (host, resolve_host(host)), sorted(candidates)))
    live = [host for host, ips in results if ips]
    return sorted(set(live))


def check_security_headers(headers: dict[str, str]) -> dict[str, str]:
    wanted = {
        "Strict-Transport-Security": "Add HSTS on HTTPS responses.",
        "Content-Security-Policy": "Add a CSP to reduce XSS impact.",
        "X-Frame-Options": "Add clickjacking protection.",
        "X-Content-Type-Options": "Add nosniff content type protection.",
        "Referrer-Policy": "Set a privacy-conscious referrer policy.",
        "Permissions-Policy": "Limit browser features where possible.",
    }
    lower = {k.lower(): v for k, v in headers.items()}
    return {name: ("present" if name.lower() in lower else advice) for name, advice in wanted.items()}


def analyze_cookies(headers: dict[str, str]) -> list[str]:
    cookies = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        lower = value.lower()
        flags = []
        if "secure" not in lower:
            flags.append("missing Secure")
        if "httponly" not in lower:
            flags.append("missing HttpOnly")
        if "samesite" not in lower:
            flags.append("missing SameSite")
        cookies.append(f"{value.split(';')[0]} ({', '.join(flags) if flags else 'good flags'})")
    return cookies


def scan_host(host: str, domain: str, ports: list[int], timeout: float, threads: int) -> HostResult:
    result = HostResult(host=host)
    result.ips = resolve_host(host)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(ports), threads) or 1) as pool:
        port_results = list(pool.map(lambda p: (p, tcp_port_open(host, p, timeout)), ports))
    result.open_ports = [port for port, is_open in port_results if is_open]

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            status, headers, body, final_url = http_get(url, timeout)
        except RuntimeError as exc:
            result.errors.append(f"{url}: {exc}")
            continue

        text = body.decode("utf-8", errors="replace")
        result.urls.append(final_url)
        result.status[final_url] = status
        result.titles[final_url] = extract_title(text)
        result.technologies[final_url] = detect_tech(headers, text)
        result.security_headers[final_url] = check_security_headers(headers)
        result.cookies[final_url] = analyze_cookies(headers)
        hrefs = extract_attrs(text, "href")
        srcs = extract_attrs(text, "src")
        result.links[final_url] = normalize_links(final_url, hrefs, domain)
        result.js_files[final_url] = [u for u in normalize_links(final_url, srcs, domain) if urlparse(u).path.endswith(".js")]
        result.forms[final_url] = extract_forms(text)

    if 443 in result.open_ports:
        result.tls = get_tls_info(host, timeout)
    return result


def fetch_extra_paths(host_results: list[HostResult], timeout: float) -> dict[str, dict[str, int]]:
    extras: dict[str, dict[str, int]] = {}
    for host in host_results:
        base_urls = [url for url in host.urls if urlparse(url).scheme == "https"] or host.urls[:1]
        if not base_urls:
            continue
        base = base_urls[0]
        extras[host.host] = {}
        for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
            url = urljoin(base, path)
            try:
                status, _, _, _ = http_get(url, timeout, max_bytes=256 * 1024)
                extras[host.host][url] = status
            except RuntimeError:
                continue
    return extras


def scan_js_files(host_results: list[HostResult], timeout: float) -> tuple[dict[str, list[str]], list[Finding]]:
    js_map: dict[str, list[str]] = {}
    findings: list[Finding] = []
    seen = sorted({js for host in host_results for files in host.js_files.values() for js in files})
    for js_url in seen[:80]:
        try:
            status, _, body, _ = http_get(js_url, timeout, max_bytes=512 * 1024)
            if status >= 400:
                continue
        except RuntimeError:
            continue
        text = body.decode("utf-8", errors="replace")
        endpoints = sorted(set(re.findall(r"['\"]((?:/|https?://)[A-Za-z0-9_./?&=%:-]{4,})['\"]", text)))
        js_map[js_url] = endpoints[:50]
        for title, pattern in SECRET_PATTERNS.items():
            if re.search(pattern, text):
                findings.append(Finding(
                    "High",
                    title,
                    js_url,
                    "Pattern matched in JavaScript file.",
                    "Review the file manually and remove secrets from client-side code.",
                ))
    return js_map, findings


def build_findings(host_results: list[HostResult], extras: dict[str, dict[str, int]]) -> list[Finding]:
    findings: list[Finding] = []
    for host in host_results:
        if host.open_ports:
            findings.append(Finding(
                "Info",
                "Open TCP ports",
                host.host,
                ", ".join(str(p) for p in host.open_ports),
                "Confirm every exposed service is intentional and patched.",
            ))
        for url, headers in host.security_headers.items():
            missing = [name for name, value in headers.items() if value != "present"]
            if missing:
                findings.append(Finding(
                    "Medium",
                    "Missing security headers",
                    url,
                    ", ".join(missing),
                    "Add the missing headers where compatible with the application.",
                ))
        for url, cookies in host.cookies.items():
            weak = [cookie for cookie in cookies if "missing" in cookie]
            if weak:
                findings.append(Finding(
                    "Medium",
                    "Cookie flags need review",
                    url,
                    "; ".join(weak[:5]),
                    "Set Secure, HttpOnly, and SameSite on sensitive cookies.",
                ))
        for url, forms in host.forms.items():
            if forms:
                findings.append(Finding(
                    "Info",
                    "Forms discovered",
                    url,
                    "; ".join(forms[:8]),
                    "Manually test form authorization, validation, CSRF, and rate limits.",
                ))
        for url, links in host.links.items():
            interesting = [link for link in links if any(word in link.lower() for word in INTERESTING_WORDS)]
            if interesting:
                findings.append(Finding(
                    "Info",
                    "Interesting URLs discovered",
                    url,
                    "; ".join(interesting[:10]),
                    "Review these endpoints manually for access control and data exposure.",
                ))
        for url in host.urls:
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
            if params:
                findings.append(Finding(
                    "Info",
                    "URL parameters discovered",
                    url,
                    ", ".join(name for name, _ in params),
                    "Manually test reflected input and server-side validation.",
                ))
        for url, status in extras.get(host.host, {}).items():
            if status < 400:
                findings.append(Finding(
                    "Info",
                    "Useful metadata file available",
                    url,
                    f"HTTP {status}",
                    "Review the file for exposed paths, contacts, or policy details.",
                ))
        for url, status in host.status.items():
            if status in {401, 403}:
                findings.append(Finding(
                    "Info",
                    "Protected endpoint found",
                    url,
                    f"HTTP {status}",
                    "Check authorization logic manually if this endpoint is in scope.",
                ))
        for url in host.urls:
            if any(fp in (host.titles.get(url, "")).lower() for fp in TAKEOVER_FINGERPRINTS):
                findings.append(Finding(
                    "High",
                    "Possible dangling service fingerprint",
                    url,
                    host.titles.get(url, ""),
                    "Verify ownership and DNS records before claiming a takeover.",
                ))
    return findings


def risk_score(findings: list[Finding]) -> int:
    weights = {"Critical": 40, "High": 25, "Medium": 10, "Low": 4, "Info": 1}
    return min(100, sum(weights.get(f.severity, 1) for f in findings))


def write_reports(
    out_dir: Path,
    domain: str,
    hosts: list[HostResult],
    extras: dict[str, dict[str, int]],
    js_endpoints: dict[str, list[str]],
    findings: list[Finding],
    started: str,
) -> None:
    ensure_dir(out_dir)
    data = {
        "tool": "Kay Bug Bounty Hunter",
        "target": domain,
        "started": started,
        "finished": now_stamp(),
        "risk_score": risk_score(findings),
        "hosts": [asdict(host) for host in hosts],
        "extra_paths": extras,
        "js_endpoints": js_endpoints,
        "findings": [asdict(finding) for finding in findings],
    }
    (out_dir / "report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")

    lines = [
        "Kay Bug Bounty Hunter Report",
        f"Target: {domain}",
        f"Started: {started}",
        f"Finished: {data['finished']}",
        f"Risk score: {data['risk_score']}/100",
        "",
        "Hosts:",
    ]
    for host in hosts:
        lines.append(f"- {host.host} ips={','.join(host.ips) or '-'} ports={','.join(map(str, host.open_ports)) or '-'}")
        for url, status in host.status.items():
            title = host.titles.get(url, "")
            lines.append(f"  - HTTP {status} {url} {title}")
    lines.extend(["", "Findings:"])
    for finding in findings:
        lines.append(f"- [{finding.severity}] {finding.title} - {finding.target}")
        lines.append(f"  Evidence: {finding.evidence}")
        lines.append(f"  Recommendation: {finding.recommendation}")
    (out_dir / "report.txt").write_text("\n".join(lines), encoding="utf-8")

    html_rows = "\n".join(
        f"<tr><td>{html.escape(f.severity)}</td><td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.target)}</td><td>{html.escape(f.evidence)}</td>"
        f"<td>{html.escape(f.recommendation)}</td></tr>"
        for f in findings
    )
    host_sections = []
    for host in hosts:
        url_items = []
        for url, status in host.status.items():
            title = html.escape(host.titles.get(url, ""))
            url_items.append(f"<li>HTTP {status}: {html.escape(url)} - {title}</li>")
        host_sections.append(
            f"<section><h2>{html.escape(host.host)}</h2>"
            f"<p><strong>IPs:</strong> {html.escape(', '.join(host.ips) or '-')}</p>"
            f"<p><strong>Open ports:</strong> {html.escape(', '.join(map(str, host.open_ports)) or '-')}</p>"
            f"<ul>{''.join(url_items)}</ul>"
            f"</section>"
        )
    host_cards = "\n".join(host_sections)
    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Kay Bug Bounty Hunter Report - {html.escape(domain)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 0; background: #07111f; color: #e5eefb; }}
    header {{ padding: 28px 36px; background: #0f1d33; border-bottom: 3px solid #00d084; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 28px; }}
    section {{ background: #101c2e; border: 1px solid #25405f; border-radius: 8px; padding: 18px; margin: 16px 0; }}
    table {{ width: 100%; border-collapse: collapse; background: #101c2e; }}
    th, td {{ border: 1px solid #25405f; padding: 10px; vertical-align: top; }}
    th {{ background: #162842; color: #99f6c8; text-align: left; }}
    code {{ color: #99f6c8; }}
  </style>
</head>
<body>
  <header>
    <h1>Kay Bug Bounty Hunter Report</h1>
    <p>Target: <code>{html.escape(domain)}</code> | Risk score: <strong>{data['risk_score']}/100</strong></p>
    <p>Started: {html.escape(started)} | Finished: {html.escape(data['finished'])}</p>
  </header>
  <main>
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Evidence</th><th>Recommendation</th></tr></thead>
      <tbody>{html_rows or '<tr><td colspan="5">No findings recorded.</td></tr>'}</tbody>
    </table>
    <h2>Hosts</h2>
    {host_cards}
  </main>
</body>
</html>
"""
    (out_dir / "report.html").write_text(html_doc, encoding="utf-8")


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    valid = sorted(p for p in ports if 1 <= p <= 65535)
    if not valid:
        raise argparse.ArgumentTypeError("Provide at least one valid TCP port.")
    if len(valid) > 200:
        raise argparse.ArgumentTypeError("Port list is too large. Keep scans focused.")
    return valid


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized bug bounty recon and web hygiene scanner.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Domain or URL in your authorized scope.")
    parser.add_argument("-o", "--output", default="bug/output", help="Output directory.")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Worker threads.")
    parser.add_argument("--timeout", type=float, default=6.0, help="Network timeout in seconds.")
    parser.add_argument("--passive", action="store_true", help="Use crt.sh passive subdomain discovery.")
    parser.add_argument("--ports", type=parse_ports, default=COMMON_PORTS, help="Comma/range TCP ports, for example 80,443,8080.")
    parser.add_argument("--yes", action="store_true", help="Confirm you have permission to scan the target.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    banner()
    if not args.yes:
        print("Add --yes to confirm this target is in your authorized bug bounty scope.")
        return 2

    try:
        domain = clean_domain(args.target)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    started = now_stamp()
    out_dir = Path(args.output)
    threads = max(1, min(args.threads, 80))
    timeout = max(1.0, args.timeout)
    ports = args.ports

    start = time.time()
    print(f"[*] Target: {domain}")
    print(f"[*] Output: {out_dir}")
    print(f"[*] Ports: {', '.join(map(str, ports))}")

    hosts = enumerate_hosts(domain, args.passive, timeout, threads)
    print(f"[+] Resolved hosts: {len(hosts)}")
    if not hosts:
        print("[-] No resolvable hosts found. Try --passive or check the domain.")
        return 1

    print("[*] Scanning hosts...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        host_results = list(pool.map(lambda h: scan_host(h, domain, ports, timeout, threads), hosts))

    print("[*] Checking metadata files...")
    extras = fetch_extra_paths(host_results, timeout)

    print("[*] Inspecting JavaScript files for endpoints and secret patterns...")
    js_endpoints, js_findings = scan_js_files(host_results, timeout)

    findings = build_findings(host_results, extras)
    findings.extend(js_findings)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.title, f.target))

    write_reports(out_dir, domain, host_results, extras, js_endpoints, findings, started)

    elapsed = round(time.time() - start, 2)
    print("\n[+] Scan complete")
    print(f"[+] Findings: {len(findings)}")
    print(f"[+] Risk score: {risk_score(findings)}/100")
    print(f"[+] Reports: {out_dir / 'report.txt'}, {out_dir / 'report.json'}, {out_dir / 'report.html'}")
    print(f"[+] Finished in {elapsed}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())