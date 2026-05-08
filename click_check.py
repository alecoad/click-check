#!/usr/bin/env python3
"""Check a list of host:port targets for clickjacking protections."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import shutil
import socket
import ssl
import sys
import threading
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


def parse_target(line: str) -> Optional[tuple[Optional[str], str, int, str]]:
    """Return (forced_scheme, host, port, path) or None if unparseable.

    Accepts: scheme://host[:port][/path], host:port[/path], host[/path].
    Path defaults to "/" when omitted; query string is preserved.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if "://" in line:
        p = urlparse(line)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        port = p.port or (443 if p.scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        return p.scheme, p.hostname, port, path
    # No scheme: split path off first slash, then parse host[:port].
    hostport, sep, path_rest = line.partition("/")
    path = "/" + path_rest if sep else "/"
    if ":" in hostport and not hostport.endswith(":"):
        host, _, port_str = hostport.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            return None
        if not host:
            return None
        return None, host, port, path
    if not hostport:
        return None
    return None, hostport, 80, path


def initial_scheme(port: int) -> str:
    return "https" if port in HTTPS_PORTS else "http"


def _origin(url: str) -> str:
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{p.hostname}:{port}"


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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # signals "do not redirect"; original response is returned


def fetch(url: str, timeout: float, insecure: bool, follow: bool) -> tuple[int, str, dict]:
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
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    with opener.open(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, resp.geturl(), headers


def probe(target: str, timeout: float, insecure: bool, follow: bool = True) -> Result:
    parsed = parse_target(target)
    if parsed is None:
        return Result(target, None, None, None, asdict(HeaderVerdict(None, "missing")),
                      asdict(HeaderVerdict(None, "missing")),
                      asdict(HeaderVerdict(None, "missing")),
                      "error", None, "could not parse target")
    forced_scheme, host, port, path = parsed
    schemes = [forced_scheme] if forced_scheme else [initial_scheme(port), "https" if initial_scheme(port) == "http" else "http"]

    last_err: Optional[str] = None
    for scheme in schemes:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            status, final_url, headers = fetch(url, timeout, insecure, follow)
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

    return Result(target, f"{schemes[0]}://{host}:{port}{path}", None, None,
                  asdict(HeaderVerdict(None, "missing")),
                  asdict(HeaderVerdict(None, "missing")),
                  asdict(HeaderVerdict(None, "missing")),
                  "error", None, last_err or "unreachable")


# ---------------- presentation layer ----------------

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "badge_vuln": "\033[97;41;1m",
    "badge_ok": "\033[30;42;1m",
    "badge_err": "\033[30;43;1m",
}
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
USE_COLOR = True


def c(s: str, *codes: str) -> str:
    if not USE_COLOR or not codes:
        return s
    return "".join(ANSI[k] for k in codes) + s + ANSI["reset"]


def vlen(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def vpad(s: str, w: int, align: str = "<") -> str:
    pad = max(0, w - vlen(s))
    if align == ">":
        return " " * pad + s
    if align == "^":
        left = pad // 2
        return " " * left + s + " " * (pad - left)
    return s + " " * pad


def trunc(s: str, w: int) -> str:
    if len(s) <= w:
        return s
    return s[: max(0, w - 1)] + "…"


def short_error(msg: str) -> str:
    """Compress noisy urllib/socket error strings into a short human label."""
    if not msg:
        return "unreachable"
    m = msg.lower()
    if "connection refused" in m:
        return "connection refused"
    if "timed out" in m or "timeout" in m:
        return "timeout"
    if "name or service not known" in m or "nodename nor servname" in m or "name resolution" in m:
        return "DNS resolution failed"
    if "no route to host" in m:
        return "no route to host"
    if "network is unreachable" in m:
        return "network unreachable"
    if "certificate verify failed" in m or "certificate has expired" in m:
        return "TLS verify failed"
    if "ssl" in m or "tls" in m:
        return "TLS error"
    if "remote end closed connection" in m or "connection reset" in m:
        return "connection reset"
    return msg.split(":", 1)[-1].strip()[:60] or "error"


def badge(verdict: str) -> str:
    if verdict == "vulnerable":
        return c(" VULN ", "badge_vuln")
    if verdict == "protected":
        return c("  OK  ", "badge_ok")
    return c(" ERR  ", "badge_err")


def banner(targets: int, workers: int, timeout: float, insecure: bool) -> str:
    title = "  click-check  ·  clickjacking scanner  "
    line = "═" * len(title)
    out = [
        c("╔" + line + "╗", "cyan"),
        c("║", "cyan") + c(title, "bold", "cyan") + c("║", "cyan"),
        c("╚" + line + "╝", "cyan"),
        f"  {c('targets:', 'dim')} {targets}   "
        f"{c('workers:', 'dim')} {workers}   "
        f"{c('timeout:', 'dim')} {timeout:g}s   "
        f"{c('tls-verify:', 'dim')} {'off' if insecure else 'on'}",
        "",
    ]
    return "\n".join(out)


def progress_line(done: int, total: int, vuln: int, ok: int, err: int, width: int = 28) -> str:
    pct = done / total if total else 1.0
    filled = int(round(pct * width))
    bar = c("█" * filled, "cyan") + c("░" * (width - filled), "grey")
    counts = (
        f"{c(str(vuln), 'red')} vuln  "
        f"{c(str(ok), 'green')} ok  "
        f"{c(str(err), 'yellow')} err"
    )
    return f"  scanning  [{bar}] {done}/{total}   {counts}"


def render_table(results: list[Result]) -> str:
    rank = {"vulnerable": 0, "error": 1, "protected": 2}
    rows_data = sorted(results, key=lambda r: (rank[r.verdict], r.input))

    headers = ["verdict", "target", "stat", "X-Frame-Options", "CSP frame-ancestors"]
    rows: list[list[str]] = []
    for r in rows_data:
        target_cell = trunc(r.url or r.input, 55)
        if r.final_url and r.url and r.final_url != r.url:
            req_origin = _origin(r.url)
            fin_origin = _origin(r.final_url)
            if req_origin != fin_origin:
                tail = _origin(r.final_url) + (urlparse(r.final_url).path or "")
            else:
                tail = urlparse(r.final_url).path or "/"
            target_cell = target_cell + " " + c("→ " + trunc(tail, 45), "dim", "magenta")
        if r.verdict == "error":
            xfo_cell = c(short_error(r.error or ""), "yellow")
            csp_cell = c("—", "dim")
            stat_cell = c("—", "dim")
        else:
            xfo_v = r.xfo["value"]
            csp_v = r.csp_frame_ancestors["value"]
            xfo_cell = (xfo_v if xfo_v is not None else c("— missing —", "red"))
            csp_cell = (csp_v if csp_v is not None else c("— missing —", "red"))
            xfo_cell = trunc(xfo_cell, 40)
            csp_cell = trunc(csp_cell, 40)
            stat_cell = str(r.status) if r.status is not None else c("—", "dim")
        rows.append([badge(r.verdict), target_cell, stat_cell, xfo_cell, csp_cell])

    widths = [max(vlen(h), max((vlen(row[i]) for row in rows), default=0)) for i, h in enumerate(headers)]
    aligns = ["^", "<", ">", "<", "<"]

    def hr(left: str, mid: str, right: str, fill: str = "─") -> str:
        return c(left + mid.join(fill * (w + 2) for w in widths) + right, "grey")

    def row(cells: list[str], style: Optional[str] = None) -> str:
        bar = c("│", "grey")
        body = bar + bar.join(
            " " + vpad(cells[i] if not style else c(cells[i], style), widths[i], aligns[i]) + " "
            for i in range(len(cells))
        ) + bar
        return body

    out = [
        hr("┌", "┬", "┐"),
        row(headers, style="bold"),
        hr("├", "┼", "┤"),
    ]
    for cells in rows:
        out.append(row(cells))
    out.append(hr("└", "┴", "┘"))
    return "\n".join(out)


def render_summary(results: list[Result], output_path: str) -> str:
    vuln = sum(1 for r in results if r.verdict == "vulnerable")
    ok = sum(1 for r in results if r.verdict == "protected")
    err = sum(1 for r in results if r.verdict == "error")
    total = len(results)

    lines_data = [
        (c("●", "red") + " " + c(f"{vuln} vulnerable", "red", "bold")),
        (c("●", "green") + " " + c(f"{ok} protected", "green")),
        (c("●", "yellow") + " " + c(f"{err} error{'s' if err != 1 else ''}", "yellow")),
        c(f"total: {total}", "dim"),
    ]
    label = " summary "
    inner = max(max(vlen(l) for l in lines_data), vlen(label) + 2, 28)
    top = c("╭─" + label + "─" * (inner - vlen(label) + 1) + "╮", "cyan")
    bot = c("╰" + "─" * (inner + 2) + "╯", "cyan")
    body = [c("│", "cyan") + " " + vpad(l, inner) + " " + c("│", "cyan") for l in lines_data]
    out = [top, *body, bot, "", c(f"results written to {output_path}", "dim")]
    return "\n".join(out)


# ---------------- CLI ----------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Check targets for clickjacking protections.")
    ap.add_argument("targets_file", help="File with one host:port per line")
    ap.add_argument("-o", "--output", default="results.json", help="JSON output file (default: results.json)")
    ap.add_argument("-w", "--workers", type=int, default=20, help="Concurrent workers (default: 20)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds (default: 10)")
    ap.add_argument("-k", "--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--no-follow", action="store_true",
                    help="Don't follow redirects; inspect headers on the exact URL")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    args = ap.parse_args(argv)

    global USE_COLOR
    USE_COLOR = sys.stdout.isatty() and not args.no_color

    try:
        with open(args.targets_file) as f:
            targets = []
            for ln in f:
                ln = ln.split("#", 1)[0].strip()  # strip inline + full-line comments
                if ln:
                    targets.append(ln)
    except OSError as e:
        print(f"error: cannot read {args.targets_file}: {e}", file=sys.stderr)
        return 2

    if not targets:
        print("error: no targets in input file", file=sys.stderr)
        return 2

    print(banner(len(targets), args.workers, args.timeout, args.insecure))

    results: list[Result] = []
    counts = {"vulnerable": 0, "protected": 0, "error": 0}
    lock = threading.Lock()
    is_tty = sys.stdout.isatty()
    term_w = shutil.get_terminal_size((100, 24)).columns

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(probe, t, args.timeout, args.insecure, not args.no_follow) for t in targets]
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            with lock:
                results.append(r)
                counts[r.verdict] += 1
                line = progress_line(len(results), len(targets),
                                     counts["vulnerable"], counts["protected"], counts["error"])
                if is_tty:
                    sys.stdout.write("\r" + line + " " * max(0, term_w - vlen(line) - 1))
                    sys.stdout.flush()
                else:
                    print(line)

    if is_tty:
        sys.stdout.write("\r" + " " * (term_w - 1) + "\r")
        sys.stdout.flush()
    print()
    print(render_table(results))
    print()
    print(render_summary(results, args.output))

    try:
        with open(args.output, "w") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
    except OSError as e:
        print(f"error: cannot write {args.output}: {e}", file=sys.stderr)
        return 2

    return 1 if counts["vulnerable"] else 0


if __name__ == "__main__":
    sys.exit(main())
