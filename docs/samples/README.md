# Sample run

This is real AuditLight output, not a mockup. A free-edition instance ran a
`perimeter` assessment against two public hosts, authorised and confirmed
through the same `/api/jobs` flow the console uses, and the results were
exported exactly as the API returned them — nothing in
[`sample-findings.json`](sample-findings.json),
[`sample-surface.json`](sample-surface.json) or
[`sample-job.json`](sample-job.json) was hand-edited.

**Source:** a lab instance of AuditLight 0.3.2, free edition (no issuer key —
`perimeter`/`web` only, 3 targets max). AI Assist was off (`GET /api/ai` in
the companion job state), so this sample shows the detection engine on its
own, not a model's narration. The two targets are hosts explicitly maintained
for security tools to test against:

| Target | Why it's a legitimate target |
|---|---|
| `scanme.nmap.org` | run by the Nmap Project specifically so scanners have a host they are authorised to probe |
| `badssl.com` | run so TLS tools have real, reproducible certificate and protocol configurations to check |

No customer host, internal network, or private deployment is reproduced here.
The operator statement, the re-typed target list, and the `entry_hash` the
authorisation log recorded are all in `sample-job.json`'s `authz` block,
exactly as AuditLight enforces for every job — sampled or not.

## What ran

Profile `perimeter` (free tier, allowed): `subdomain`, `portscan`, `banner`,
`httpprobe`, `headers`, `tlsaudit`, `vulnsig` — 7 of the 9 built-in checks.
`secrets` and the four subprocess tools (`nuclei`, `testssl.sh`, `lynis`,
`nmap`) are not part of this profile or not installed on the lab host.
`sample-job.json`'s `adapters` array shows each check's real start time,
duration and finding count, run twice (once per target).

## What AuditLight found

40 findings total across both targets — 1 high, 11 medium, 13 low, 15 info —
the exact counts the job reports. A sample, not the full list:

| Target | Port | Category | Severity | Title |
|---|---|---|---|---|
| `scanme.nmap.org` | 80 | vuln | **high** | Apache httpd 2.4.7 is affected by known issues (CVE-2021-41773, CVE-2021-42013) |
| `badssl.com` | 443 | tls | medium | TLS 1.0 is still accepted |
| `badssl.com` | 443 | tls | medium | 8 cipher suite(s) considered insecure are accepted |
| `badssl.com` | 443 | tls | medium | TLS 1.1 is still accepted |
| `scanme.nmap.org` | 22 | vuln | medium | OpenSSH 6.6.1 is affected by known issues |
| `badssl.com` / `scanme.nmap.org` | 80/443 | web | medium | Content Security Policy is not set (3 targets×ports) |
| `badssl.com` | 443 | web | medium | HSTS is not set |
| `badssl.com` / `scanme.nmap.org` | 80 | vuln | medium | nginx 1.10.3 is affected by known issues |

The `vulnsig` check matched the version strings `httpprobe` and `banner`
actually observed against an embedded signature set — it is a version-match,
not a live exploit attempt, and both finding descriptions in
`sample-findings.json` say so explicitly ("confirm the build before treating
it as exploitable"). The remaining 25 findings are the `low`/`info` tail:
missing security headers (`X-Content-Type-Options`, `Referrer-Policy`,
framing), server-header disclosure, and the one `info` finding per root that
records the host itself was added to the assessment.

## The surface map

`sample-surface.json` is the same attack-surface graph the Surface Explorer
draws on screen and the Assessment Report prints as an inline tree: two
roots (`badssl.com`, `scanme.nmap.org`), the services actually observed
beneath each (`svc:badssl.com:80`, `svc:badssl.com:443`, …), and the finding
IDs attached to each node — not inferred topology, only what a check
actually reached, exactly as the main README's "Seeing the surface" section
describes.

## What this sample does not show

Free tier cannot run `hardening` or `full` (both `needs_paid`), so this
sample has no `secrets` findings and no `lynis` output — and
`GET /api/jobs/{id}/export.json` correctly refuses with the upgrade message
in `sample-job.json`'s sibling call, reproduced here: *"Machine-readable
export is available on the Pro and Team tiers."* Re-assessment and the
Change Report (new/regressed/persisting/improved/resolved) need a second run
against a saved definition, which this one-off sample job does not have —
see the main README's "Tracking change over time" section for how that
works on a paid licence.
