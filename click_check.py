#!/usr/bin/env python3
"""Check a list of host:port targets for clickjacking protections."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Optional
from urllib.parse import urlparse

USER_AGENT = "click-check/1.0"
HTTPS_PORTS = {443, 8443, 9443}


@dataclass
class HeaderVerdict:
    value: Optional[str]
    verdict: str  # protected | weak | missing


@dataclass
class Result:
    input: str
    url: Optional[str]
    final_url: Optional[str]
    status: Optional[int]
    xfo: dict
    csp_frame_ancestors: dict
    csp_report_only_frame_ancestors: dict
    verdict: str  # vulnerable | protected | error
    scheme_used: Optional[str]
    error: Optional[str]


def parse_target(line: str) -> Optional[tuple[Optional[str], str, int]]:
    """Return (forced_scheme, host, port) or None if unparseable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    forced_scheme: Optional[str] = None
    if "://" in line:
        p = urlparse(line)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        forced_scheme = p.scheme
        host = p.hostname
        port = p.port or (443 if forced_scheme == "https" else 80)
        return forced_scheme, host, port
    if ":" in line and not line.endswith(":"):
        host, _, port_str = line.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            return None
        if not host:
            return None
        return None, host, port
    # bare host
    return None, line, 80


def initial_scheme(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


def classify_xfo(value: Optional[str]) -> HeaderVerdict:
    if value is None:
        return HeaderVerdict(None, "missing")
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return HeaderVerdict(value, "protected")
    return HeaderVerdict(value, "weak")


def extract_frame_ancestors(csp: Optional[str]) -> Optional[list[str]]:
    if not csp:
        return None
    for directive in csp.split(";"):
        parts = directive.strip().split()
        if not parts:
            continue
        if parts[0].lower() == "frame-ancestors":
            return [s.strip() for s in parts[1:]]
    return None


def classify_csp(csp: Optional[str]) -> HeaderVerdict:
    sources = extract_frame_ancestors(csp)
    if sources is None:
        return HeaderVerdict(csp, "missing")
    raw = " ".join(sources)
    lowered = [s.lower() for s in sources]
    if "'none'" in lowered:
        return HeaderVerdict(raw, "protected")
    if "*" in sources:
        return HeaderVerdict(raw, "weak")
    if sources:
        return HeaderVerdict(raw, "protected")
    return HeaderVerdict(raw, "missing")


def fetch(url: str, timeout: float, insecure: bool) -> tuple[int, str, dict]:
    """Return (status, final_url, headers_dict_lower). Raises on failure."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0", "Accept": "*/*"},
        method="GET",
    )
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, resp.geturl(), headers


def probe(target: str, timeout: float, insecure: bool) -> Result:
    parsed = parse_target(target)
    if parsed is None:
        return Result(target, None, None, None, asdict(HeaderVerdict(None, "missing")),
                      asdict(HeaderVerdict(None, "missing")),
                      asdict(HeaderVerdict(None, "missing")),
                      "error", None, "could not parse target")
    forced_scheme, host, port = parsed
    schemes = [forced_scheme] if forced_scheme else [initial_scheme(port), "https" if initial_scheme(port) == "http" else "http"]

    last_err: Optional[str] = None
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}/"
        try:
            status, final_url, headers = fetch(url, timeout, insecure)
        except urllib.error.HTTPError as e:
            # HTTPError still carries headers; treat as a successful probe
            try:
                hdrs = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            except Exception:
                hdrs = {}
            status, final_url, headers = e.code, url, hdrs
        except (urllib.error.URLError, ssl.SSLError, socket.timeout, ConnectionError, OSError) as e:
            last_err = f"{type(e).__name__}: {e}"
            continue
        except Exception as e:  # be defensive: never crash the worker
            last_err = f"{type(e).__name__}: {e}"
            continue

        xfo = classify_xfo(headers.get("x-frame-options"))
        csp = classify_csp(headers.get("content-security-policy"))
        csp_ro_value = extract_frame_ancestors(headers.get("content-security-policy-report-only"))
        csp_ro = HeaderVerdict(
            " ".join(csp_ro_value) if csp_ro_value is not None else None,
            "protected" if csp_ro_value and "'none'" in [s.lower() for s in csp_ro_value] else "weak" if csp_ro_value else "missing",
        )

        if xfo.verdict == "protected" or csp.verdict == "protected":
            verdict = "protected"
        else:
            verdict = "vulnerable"

        return Result(target, url, final_url, status, asdict(xfo), asdict(csp), asdict(csp_ro),
                      verdict, scheme, None)

    return Result(target, f"{schemes[0]}://{host}:{port}/", None, None,
                  asdict(HeaderVerdict(None, "missing")),
                  asdict(HeaderVerdict(None, "missing")),
                  asdict(HeaderVerdict(None, "missing")),
                  "error", None, last_err or "unreachable")


def color(s: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{s}\033[0m" if enabled else s


def render(result: Result, use_color: bool) -> str:
    if result.verdict == "vulnerable":
        tag = color("[VULN]", "31;1", use_color)
    elif result.verdict == "protected":
        tag = color("[OK]  ", "32;1", use_color)
    else:
        tag = color("[ERR] ", "33;1", use_color)

    url = result.final_url or result.url or result.input
    if result.verdict == "error":
        return f"{tag} {url:<45}  {result.error}"
    xfo = result.xfo["value"] or "-"
    csp = result.csp_frame_ancestors["value"] or "-"
    return f"{tag} {url:<45}  XFO={xfo}  CSP={csp}"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check targets for clickjacking protections.")
    ap.add_argument("targets_file", help="File with one host:port per line")
    ap.add_argument("-o", "--output", default="results.json", help="JSON output file (default: results.json)")
    ap.add_argument("-w", "--workers", type=int, default=20, help="Concurrent workers (default: 20)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds (default: 10)")
    ap.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    args = ap.parse_args(argv)

    try:
        with open(args.targets_file) as f:
            targets = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    except OSError as e:
        print(f"error: cannot read {args.targets_file}: {e}", file=sys.stderr)
        return 2

    if not targets:
        print("error: no targets in input file", file=sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color
    results: list[Result] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(probe, t, args.timeout, args.insecure): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            results.append(r)
            print(render(r, use_color), flush=True)

    try:
        with open(args.output, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
    except OSError as e:
        print(f"error: cannot write {args.output}: {e}", file=sys.stderr)
        return 2

    vuln = sum(1 for r in results if r.verdict == "vulnerable")
    ok = sum(1 for r in results if r.verdict == "protected")
    err = sum(1 for r in results if r.verdict == "error")
    print(f"\n{vuln} vulnerable / {ok} protected / {err} errors out of {len(results)} targets")
    print(f"results written to {args.output}")
    return 1 if vuln else 0


if __name__ == "__main__":
    sys.exit(main())
