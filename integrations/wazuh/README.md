# Mantis DNS → Wazuh integration

Mantis's SIEM export (`docs/design.md` §20) offers three paths: a
cursor-based pull API, an HMAC-signed webhook push, and RFC 5424 syslog
(§20.8). Wazuh has no generic inbound HTTP receiver that understands
Mantis's push contract (custom `X-Mantis-Signature` header, JSON/CEF body)
— it ingests via agent traffic, a syslog listener, or local log tailing, not
arbitrary webhooks.

**Prefer the syslog sink for new setups**: Wazuh's built-in `<remote>`
listener (UDP/TCP 514) consumes a Mantis `SiemSyslog` sink directly — add
one from the control plane's Settings → Integrations page, pointed at the
Wazuh manager, format `cef`. No script, no cron, no local polling account.
See `docs/design.md` §20.8 for the message format and `<remote>` config on
the Wazuh side.

The pull-script bridge documented below predates syslog support and remains
useful if you'd rather not open an inbound listener on the Wazuh manager, or
are already running it. It requires nothing listening on the Wazuh side
beyond what ships by default.

## How it works

```
[cron / wazuh "command" wodle]
        │  every N seconds
        ▼
mantis_siem_pull.py  ── GET /api/v1/siem/events?after_id=<cursor> ──▶  Mantis control plane
        │  appends one JSON object per line, advances cursor
        ▼
/var/ossec/logs/mantis/siem-events.json
        │  <localfile><log_format>json</log_format></localfile>
        ▼
Wazuh analysisd  ── built-in JSON decoder (automatic, no custom decoder needed) ──▶  rules in local_rules.xml
```

Wazuh's JSON log format decodes every top-level key automatically
(`qname`, `decision`, `client_ip`, `matched_category`, `tags`, …) — you get
fields for free. `local_rules.xml` only adds the *alerting* logic on top.

## Setup

1. **Create a dedicated Mantis account** for this integration with the
   `operator` role (sufficient for `GET /siem/events`; see
   `require_role("admin", "operator")` in
   `services/control/mantis_control/api/siem_routers.py`). Don't reuse an
   interactive admin login.

2. **Copy the integration files** to the Wazuh manager:
   ```
   /var/ossec/integrations/mantis/mantis_siem_pull.py
   /var/ossec/integrations/mantis/run-mantis-pull.sh   (chmod +x)
   ```

3. **Configure credentials** — copy `wazuh-integration.env.example` to
   `/etc/mantis/wazuh-integration.env`, fill in `MANTIS_API_URL`,
   `MANTIS_EMAIL`, `MANTIS_PASSWORD`, then `chmod 600` it (root-only —
   it's a plaintext credential, same sensitivity as any other Wazuh wodle
   secret).

4. **Wire up ossec.conf** — merge `ossec.conf.snippet.xml` into
   `/var/ossec/etc/ossec.conf` (inside `<ossec_config>`). Adjust the
   `<interval>` to your desired poll cadence (1m is a reasonable default;
   the Mantis pull API has no rate limit of its own, but there's no reason
   to poll faster than you need alerts).

5. **Install the rules** — copy `local_rules.xml` to
   `/var/ossec/etc/rules/local_rules.xml`, or merge its `<rule>` blocks
   into an existing local rules file (a manager only loads one). Rule IDs
   100100–100106 are used; bump them if that range is already taken.

6. **Restart**: `systemctl restart wazuh-manager`.

7. **Verify**: `run-mantis-pull.sh` once by hand, check
   `/var/ossec/logs/mantis/siem-events.json` gets JSON lines appended, then
   `tail -f /var/ossec/logs/alerts/alerts.log | grep mantis_dns` after a
   block event occurs.

## What the shipped rules cover

| Rule ID | Level | Fires on |
|---|---|---|
| 100100 | 3 | Any Mantis DNS event (base rule, not itself alert-worthy) |
| 100101 | 3 | Allowed query |
| 100102 | 7 | Blocked query |
| 100103 | 10 | Blocked query, category = malware |
| 100104 | 10 | Blocked query, category = phishing |
| 100105 | 8 | Blocked query from a device tagged `unmanaged` |
| 100106 | 10 | 5+ blocked queries from the same `client_ip` within 120s (frequency rule — possible compromised host) |

These map directly to the example SIEM rules in `docs/design.md` §20.6.
Extend with more `matched_category` values, `tenant_id`/`group_id` scoping,
or additional `tags` correlation as needed — every field in the schema
(§20.2) is available to rule authors once it lands in the JSON log line.

## About webhook push and private IPs

Earlier, Mantis's SSRF guard rejected *any* webhook URL pointing at a
private/RFC-1918 address — which meant an on-prem Wazuh (the common case)
couldn't even be configured as a push target, receiver aside. That's been
narrowed for SIEM webhooks specifically (`check_webhook_url_safe` in
`services/control/mantis_control/ssrf_guard.py`): private targets are now
allowed, only loopback/link-local/cloud-metadata addresses stay blocked.
This doesn't make push work with stock Wazuh (see above — there's still
nothing listening for it), but it's no longer blocked at the network-policy
layer if you build your own receiver (e.g. a small shim that verifies the
HMAC and writes to a file Wazuh tails) or point it at a SIEM that *does*
accept generic webhooks.

## Syslog (recommended for new setups)

See the note at the top of this document — a Mantis `SiemSyslog` sink
(`docs/design.md` §20.8) feeds Wazuh's `<remote>` syslog listener directly,
no pull script required:

```xml
<!-- /var/ossec/etc/ossec.conf -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>  <!-- or udp, matching the sink's transport -->
</remote>
```

CEF lines land in Wazuh the same way any syslog-fed CEF source does —
`local_rules.xml`'s rule bodies can be adapted from JSON-field matches to
the CEF extension keys (`cs1`=matched_category, `act`=decision, etc., see
`docs/design.md` §20.5) if you migrate an existing pull-based setup.
