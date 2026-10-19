# SHAFRA — Odoo mail link-preview SSRF detector

`odoo_ssrf_in_mail.py` detects the **`/mail/link_preview` server-side request
forgery (SSRF)** in Odoo's mail link-preview fetcher.

- Upstream sink: [`addons/mail/tools/link_preview.py`](https://github.com/odoo/odoo/blob/17.0/addons/mail/tools/link_preview.py)
- Storage / trigger: [`addons/mail/models/mail_link_preview.py`](https://github.com/odoo/odoo/blob/17.0/addons/mail/models/mail_link_preview.py)
- Public endpoint: [`addons/mail/controllers/link_preview.py`](https://github.com/odoo/odoo/blob/17.0/addons/mail/controllers/link_preview.py)
- Odoo security policy: [`SECURITY.md`](https://github.com/odoo/odoo/blob/17.0/SECURITY.md)

> **AUTHORIZED SECURITY TESTING ONLY.** Use this only against Odoo instances
> you own or are **explicitly, in writing,** authorized to test (signed
> engagement or bug-bounty scope). Unauthorized testing is illegal in most
> jurisdictions (CFAA, UK CMA, and equivalents). This tool is detection-only:
> it does not scan internal networks and does not exfiltrate data.

---

## What it does

It answers one question:

> Does this Odoo instance make a server-side HTTP request to a URL that a
> low-privileged / portal user can cause to be previewed?

How it proves it **without any external callback**:

1. Logs in with credentials you provide.
2. Creates a `mail.message` whose body contains a link to a probe URL
   (**Wikipedia by default**).
3. Triggers `/mail/link_preview`.
4. Reads the stored link preview back from the instance via
   `mail.message` → `message_format` → `linkPreviews`.
5. If the instance stored a preview for that URL → **VULNERABLE**.

Because the proof is read back from the instance itself, you don't need a
listener or a webhook. If you'd rather observe the request on your own
infrastructure, pass `--probe-url` pointing at your own webhook/server.

---

## Requirements

- Python 3.8+
- `requests`

```bash
pip install requests
```

---

## Usage

### Detect with the default probe (Wikipedia)

```bash
python3 odoo_ssrf_in_mail.py \
    --url https://odoo.example.com \
    --username test@example.com \
    --password 'secret' \
    --db mydb
```

Expected when vulnerable:

```
  RESULT: VULNERABLE  (server-side fetch confirmed)
  The instance fetched our URL and stored a link preview:
    source_url : https://en.wikipedia.org/wiki/Odoo?t=...
    og_title   : Odoo - Wikipedia
```

### Use your own webhook / server as the probe

Two requirements for the probe URL:

1. It must be **reachable from the Odoo server** (a public URL).
2. It must return **`Content-Type: text/html`** — the fetcher discards any
   other content type, so JSON/plain-text endpoints will produce no preview.

```bash
python3 odoo_ssrf_in_mail.py \
    --url https://odoo.example.com \
    --username test@example.com \
    --password 'secret' \
    --db mydb \
    --insecure \
    --probe-url https://your-server.example/ssrf-probe.html
```

Then also check your webhook/server logs for a request coming from the
target server's IP. (That is the strongest confirmation when you control the
receiver.)

#### When your receiver does NOT return text/html (e.g. webhook.site)

Odoo only stores a preview when the response is `Content-Type: text/html`, so
a webhook that returns JSON/plain text will still be **fetched** but nothing
is stored — the instance read-back is empty. In that case:

1. Run with your webhook as `--probe-url`.
2. Check your webhook inbox/logs for a request from the target's IP.
3. **If you see the hit, the target IS vulnerable.** Re-run with `--probe-hit`
   so the tool records that verdict:

```bash
python3 odoo_ssrf_in_mail.py \
    --url https://odoo.example.com \
    --username test@example.com \
    --password 'secret' \
    --db mydb \
    --insecure \
    --probe-url https://webhook.site/<your-id> \
    --probe-hit
```

> Why the separate flag? Two different proofs are possible:
> - **Read-back** (default Wikipedia probe): Odoo *stored* a preview → the
>   server fetched an HTML page. Self-contained, no infrastructure.
> - **Webhook hit** (custom probe): Odoo fetched a URL you control and the
>   request landed on *you*. The script can't see your webhook, so you confirm
>   it with `--probe-hit`.
>
> A tool that printed a flat "NOT VULNERABLE" just because your non-HTML
> webhook produced no stored preview would be wrong — that is exactly the case
> `--probe-hit` / the `INCONCLUSIVE` verdict handle.

---

## Options

| Option          | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| `--url`         | Base URL of the Odoo instance (required)                                    |
| `--username`    | Login / email of the test account (required)                                |
| `--password`    | Password of the test account (required)                                     |
| `--db`          | Database name (optional; auto-detected when omitted)                        |
| `--probe-url`   | URL used as the probe. **Must return `Content-Type: text/html`.** Default: `https://en.wikipedia.org/wiki/Odoo`. Replace with your own webhook/server if you want to observe the request yourself. |
| `--wait`        | Seconds to wait before reading the preview back (default `5`)               |
| `--insecure`    | Do not verify TLS certificates (needed for self-signed certs)               |
| `--debug`       | Print extra diagnostics (e.g. why message creation failed)                  |
| `--probe-hit`   | With a custom `--probe-url`: you confirmed the target hit your receiver. Reports `VULNERABLE` from that hit. |

---

## Notes & troubleshooting

- **Self-signed certificate** → add `--insecure`.
- **`NOT CONFIRMED` but you think it should work**:
  - The probe URL may not return `text/html` (JSON/plain text is discarded).
  - The probe URL may not be reachable from the target.
  - Per-domain throttling (Odoo previews a domain at most once per 10s) —
    the tool auto-uniquifies the URL each run; just retry.
  - The account may not be allowed to create messages.
- **Why Wikipedia by default?** It is a stable, always-up `text/html` page
  with Open Graph tags, so the detector needs no infrastructure of its own.
  Swap it for your own receiver via `--probe-url` when you want to log the hit.

---

## Legal

This software is provided for defensive research and education. The author
accepts no liability for misuse or damage. By using it you accept full
responsibility for your actions. Test only systems you are authorized to test.
