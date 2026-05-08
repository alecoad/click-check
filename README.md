# click-check

Standalone Python 3 script that checks a list of `host:port` targets for clickjacking protections (`X-Frame-Options` and CSP `frame-ancestors`).

## Usage

```
python3 click_check.py targets.txt [-o results.json] [-w 20] [--timeout 10] [-k] [--no-follow]
```

- `targets.txt`: one target per line. Accepts:
  - `host:port` — e.g. `10.0.0.5:8080`
  - `host:port/path` — e.g. `10.0.0.5:8080/admin`
  - `scheme://host[:port][/path]` — e.g. `https://app.example.com/login`
  - bare `host` (defaults to port 80)
- Lines starting with `#`, blank lines, and inline `# comments` are stripped.
- `-k / --insecure`: skip TLS verification (useful for internal IPs with self-signed certs).
- `--no-follow`: don't follow 3xx redirects; inspect headers on the exact URL.
- By default redirects are followed and the **final** URL is the one inspected. When the final URL differs from the request, the table appends a dim `→ ...` indicator.
- Exit code: `0` if no vulnerable targets, `1` if any vulnerable, `2` on usage error.

## Verdicts

- **protected** — `X-Frame-Options: DENY|SAMEORIGIN` OR a non-`*` CSP `frame-ancestors` directive.
- **vulnerable** — neither protection present (or both are `*` / `ALLOW-FROM`-style).
- **error** — could not connect on either inferred scheme.

Detailed per-target headers are written to `results.json`.

## Example

```
python3 click_check.py targets.example.txt
```

## Credits

Built with [Claude Code](https://claude.com/claude-code) (Opus 4.7).

