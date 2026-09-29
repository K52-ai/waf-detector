#!/usr/bin/env python3

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

VERSION = "1.0.0"
TOOL    = "waf-detector"
AUTHOR  = "K52-ai"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")

DEFAULT_TIMEOUT = 15

RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"

RED     = "\033[91m"
YEL     = "\033[93m"
GRN     = "\033[92m"
CYN     = "\033[96m"
BLU     = "\033[94m"
MAG     = "\033[95m"
WHT     = "\033[97m"

RAINBOW = [RED, YEL, GRN, CYN, BLU, MAG]


def hue_color(h):
    h = h % 6.0
    if h < 1:   return RED
    if h < 2:   return YEL
    if h < 3:   return GRN
    if h < 4:   return CYN
    if h < 5:   return BLU
    return MAG


def rainbow(s):
    out = []
    for i, ch in enumerate(s):
        out.append(RAINBOW[i % len(RAINBOW)])
        out.append(ch)
    out.append(RESET)
    return "".join(out)


def gradient(s):
    if not s:
        return ""
    out = []
    n = len(s)
    for i, ch in enumerate(s):
        hue = (i / n) * 6.0
        out.append(hue_color(hue))
        out.append(ch)
    out.append(RESET)
    return "".join(out)


def info(msg, *a):
    print(f"{CYN}[*]{RESET} {msg % a if a else msg}")

def good(msg, *a):
    print(f"{GRN}[+]{RESET} {msg % a if a else msg}")

def warn(msg, *a):
    print(f"{YEL}[!]{RESET} {msg % a if a else msg}")

def bad(msg, *a):
    print(f"{RED}[-]{RESET} {msg % a if a else msg}")

def detail(msg, *a):
    print(f"    {DIM}{msg % a if a else msg}{RESET}")


def banner():
    art = [
        r"  █   █  █████   ███         ███   ███ ",
        r"  █  █   █      █   █       █   █   █  ",
        r"  ███    ████      █  ████  █████   █  ",
        r"  █  █      █   █        █  █   █   █  ",
        r"  █   █ ████   █████      █ █   █  ███ ",
    ]
    print()
    for line in art:
        print(gradient(line))
    print()
    print(f"              {BOLD}{WHT}waf detector v{VERSION}{RESET}")
    print(f"              {DIM}{'─' * 45}{RESET}")
    print()
    print(rainbow("                  by K52-ai"))
    print()


class HTTPClient:
    def __init__(self, timeout=DEFAULT_TIMEOUT, proxy=None):
        self.timeout = timeout
        self.proxy = proxy

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        handlers = [
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPRedirectHandler(),
        ]
        if proxy:
            handlers.append(urllib.request.ProxyHandler({
                "http": proxy, "https": proxy,
            }))
        self.opener = urllib.request.build_opener(*handlers)

    def request(self, url, method="GET", headers=None, body=None):
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", UA)
        headers.setdefault("Accept", "*/*")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        start = time.perf_counter()
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                data = r.read(8192)
                code = r.status
                hdrs = dict(r.headers)
                return {
                    "status": code,
                    "headers": hdrs,
                    "body": data,
                    "elapsed": time.perf_counter() - start,
                    "error": None,
                }
        except urllib.error.HTTPError as e:
            data = e.read(8192) if e.fp else b""
            return {
                "status": e.code,
                "headers": dict(e.headers),
                "body": data,
                "elapsed": time.perf_counter() - start,
                "error": None,
            }
        except Exception as e:
            return {
                "status": None,
                "headers": {},
                "body": b"",
                "elapsed": time.perf_counter() - start,
                "error": str(e),
            }


def load_signatures(path):
    if not os.path.isfile(path):
        bad("signatures file not found: %s", path)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def match_headers(signature, headers):
    evidence = []
    patterns = signature.get("headers", {})
    lower = {k.lower(): str(v).lower() for k, v in headers.items()}

    for hname, hval in patterns.items():
        hname = hname.lower()
        if hname not in lower:
            continue
        if hval == "*":
            evidence.append(f"Header: {hname}: {lower[hname]}")
            continue
        pattern = hval.lower().replace("*", ".*")
        if re.search(pattern, lower[hname]):
            evidence.append(f"Header: {hname}: {lower[hname]}")
    return evidence


def match_cookies(signature, headers):
    evidence = []
    cookies = signature.get("cookies", [])
    if not cookies:
        return evidence

    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    if not raw:
        return evidence
    raw_lower = raw.lower()

    for ck in cookies:
        if ck.lower() in raw_lower:
            evidence.append(f"Cookie: {ck}")
    return evidence


def match_body(signature, body):
    evidence = []
    patterns = signature.get("body_patterns", [])
    if not patterns or not body:
        return evidence

    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return evidence
    text_lower = text.lower()

    for p in patterns:
        if p.lower() in text_lower:
            evidence.append(f"Body: contains '{p}'")
    return evidence


def detect_waf(client, target):
    result = client.request(target)
    if result["error"]:
        bad("cannot reach target: %s", result["error"])
        return None

    signatures = load_signatures("waf_signatures.json")
    matches = []

    for key, sig in signatures.items():
        evidence = []
        evidence += match_headers(sig, result["headers"])
        evidence += match_cookies(sig, result["headers"])
        evidence += match_body(sig, result["body"])

        if evidence:
            confidence = sig.get("confidence", "medium")
            score = len(evidence) * (2 if confidence == "high" else 1)
            matches.append({
                "key": key,
                "name": sig.get("name", key),
                "type": sig.get("type", "unknown"),
                "confidence": confidence,
                "score": score,
                "evidence": evidence,
            })

    matches.sort(key=lambda m: m["score"], reverse=True)
    return {
        "target": target,
        "status": result["status"],
        "server": result["headers"].get("Server", ""),
        "matches": matches,
    }


def probe_waf_behavior(client, base):
    findings = []

    payloads = [
        ("SQLi", "/?id=1' OR '1'='1"),
        ("SQLi", "/?id=1 UNION SELECT 1,2,3--"),
        ("XSS", "/?q=<script>alert(1)</script>"),
        ("XSS", "/?q=\"><svg/onload=alert(1)>"),
        ("LFI", "/?file=../../../../etc/passwd"),
        ("LFI", "/?file=php://filter/convert.base64-encode/resource=index"),
        ("RCE", "/?cmd=;cat /etc/passwd"),
        ("RCE", "/?cmd=|whoami"),
        ("Traversal", "/../../../etc/passwd"),
        ("Scanner-UA", None),
    ]

    for label, path in payloads:
        url = base.rstrip("/") + path if path else base
        if label == "Scanner-UA":
            headers = {"User-Agent": "sqlmap/1.7.2#stable"}
            result = client.request(url, headers=headers)
        else:
            result = client.request(url)

        status = result["status"]
        body_size = len(result["body"])
        blocked = status in (400, 403, 406, 419, 429, 500, 501, 503)
        findings.append({
            "attack": label,
            "status": status,
            "body_size": body_size,
            "blocked": blocked,
        })

    return findings


def bypass_tips(waf_name):
    name = waf_name.lower()

    if "cloudflare" in name:
        return [
            "Use unicode escaping for SQL keywords (\\u0053\\u0045\\u004c\\u0045\\u0043\\u0054)",
            "Send Origin and Referer headers matching the target",
            "Use ?rest_route=/path instead of /wp-json/path",
            "Add random padding to bypass fixed-size inspection windows",
            "Slow down requests to avoid rate limiting",
        ]
    if "sucuri" in name:
        return [
            "Rotate User-Agent per request",
            "Send valid Accept-Language and Accept-Encoding",
            "Use POST with JSON body instead of GET query strings",
            "Split payloads across multiple parameters",
        ]
    if "imperva" in name or "incapsula" in name:
        return [
            "Solve the JS challenge cookie (visid_incap_*)",
            "Replay the session cookie",
            "Use HTTP/2 with header ordering tricks",
            "Slow down to avoid rate limits",
        ]
    if "aws" in name:
        return [
            "Use multipart/form-data with payload split across parts",
            "Base64-encode payload fragments",
            "Rotate User-Agent and X-Forwarded-For",
        ]
    if "akamai" in name:
        return [
            "Handle bm_sv and _abck cookies",
            "Use residential proxies",
            "Rotate IPs frequently",
        ]
    if "f5" in name or "big-ip" in name:
        return [
            "Case-alternate SQL keywords (SeLeCt)",
            "Use inline comments (/**/) between tokens",
            "URL-encode twice",
        ]
    if "wordfence" in name:
        return [
            "Rotate User-Agent",
            "Slow requests below rate limit threshold",
            "Avoid known scanner signatures",
        ]
    if "modsecurity" in name:
        return [
            "Case-alternate keywords",
            "Use SQL comment tricks",
            "Encode with backslash sequences",
        ]
    return [
        "Try case-alternation for keywords",
        "Use URL encoding variants",
        "Add random padding",
        "Rotate User-Agent",
        "Slow down requests",
    ]


def print_report(report, behavior, verbose=False):
    print()
    print(f"{BOLD}{CYN}═══ WAF Detection Report ═══{RESET}")
    print()
    print(f"{BOLD}Target:{RESET}  {report['target']}")
    print(f"{BOLD}Status:{RESET}  {report['status']}")
    if report["server"]:
        print(f"{BOLD}Server:{RESET}  {report['server']}")
    print()

    if not report["matches"]:
        warn("no WAF detected from signatures")
        return

    best = report["matches"][0]
    print(f"{GRN}█ WAF DETECTED:{RESET} {BOLD}{YEL}{best['name']}{RESET}")
    print(f"{GRN}  ├─ Type:{RESET}       {best['type']}")
    print(f"{GRN}  ├─ Confidence:{RESET} {best['confidence'].upper()}")
    print(f"{GRN}  ├─ Evidence:{RESET}")
    for ev in best["evidence"]:
        print(f"{GRN}  │   ├─{RESET} {ev}")

    print(f"{GRN}  └─ Bypass techniques:{RESET}")
    for tip in bypass_tips(best["name"]):
        print(f"{GRN}      ├─{RESET} {tip}")
    print()

    if len(report["matches"]) > 1:
        print(f"{CYN}Other possible matches:{RESET}")
        for m in report["matches"][1:]:
            print(f"    {DIM}- {m['name']} ({m['confidence']}){RESET}")
        print()

    if behavior:
        blocked = [b for b in behavior if b["blocked"]]
        passed = [b for b in behavior if not b["blocked"]]
        print(f"{BOLD}{CYN}Behavioral analysis:{RESET}")
        print(f"    Blocked: {len(blocked)}/{len(behavior)}")
        print(f"    Passed:  {len(passed)}/{len(behavior)}")
        if verbose:
            print()
            for b in behavior:
                marker = f"{RED}[BLOCKED]{RESET}" if b["blocked"] else f"{GRN}[PASSED]{RESET}"
                print(f"    {marker} {b['attack']:<12} status={b['status']}")
        print()


def save_json(report, behavior, path):
    out = {
        "target": report["target"],
        "status": report["status"],
        "server": report["server"],
        "waf": report["matches"][0]["name"] if report["matches"] else None,
        "confidence": report["matches"][0]["confidence"] if report["matches"] else None,
        "matches": report["matches"],
        "behavior": behavior,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    good("saved to %s", path)


def main():
    parser = argparse.ArgumentParser(
        prog="waf-detector",
        description="Detect and fingerprint Web Application Firewalls",
    )
    parser.add_argument("target", nargs="?", help="target URL")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("-j", "--json", action="store_true",
                        help="save JSON report to waf_report.json")
    parser.add_argument("--behavior", action="store_true",
                        help="run behavioral probes (blocks/passes)")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    banner()

    target = args.target
    if not target:
        try:
            target = input(f"{CYN}Target:{RESET} ").strip()
        except EOFError:
            target = ""
    if not target:
        bad("no target given")
        return 2

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print()
    info("Target:  %s", target)
    info("Timeout: %ds", args.timeout)
    print()
    info("analyzing headers and cookies ...")

    client = HTTPClient(timeout=args.timeout, proxy=args.proxy)

    report = detect_waf(client, target)
    if report is None:
        return 1

    behavior = []
    if args.behavior:
        info("running behavioral probes ...")
        behavior = probe_waf_behavior(client, target)

    print_report(report, behavior, verbose=args.verbose)

    if args.json:
        save_json(report, behavior, "waf_report.json")

    return 0


if __name__ == "__main__":
    sys.exit(main())
