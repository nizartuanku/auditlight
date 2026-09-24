# Changelog

## 0.3.2 — 2026-09-24

- **AI Assist (optional): an ✨ Explain button on every finding, and ✨ Why did this disappear?
  on findings gone since the previous run.** When AuditLight is started with `-ai-assist-url`,
  a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar explains a finding in
  plain language and lists what to verify. The engine remains the only source of findings,
  severity and change classification: the reason a finding disappeared (target skipped, check
  did not complete, no longer detected) is read from AuditLight's own process record and shown
  next to the narrative; the model never decides it and "fixed" is never claimed. Only one
  sanitised finding is sent (secret-like evidence dropped; matched credentials and header
  dumps never forwarded). Any AI failure shows a quiet note and changes nothing. Free edition:
  a sidecar on the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai`, `POST /api/jobs/{id}/findings/explain` and `POST /api/jobs/{id}/delta/explain`,
  covered by tests for: AI off, bad config, sanitising, tier gating, engine-owned
  classification, sidecar down, and bad requests.
- The results page now lists findings that were present in the previous run of a saved
  assessment and are absent from this one, with the same "gone is not fixed" wording as the
  change report.

## 0.3.1 — 2026-09-23

- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, `cd`s into the extracted directory, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides). Step 1 uses the unauthenticated GitHub API, which allows 60 calls per hour per address; when that budget is gone the script names the rate limit and when it resets, instead of reporting "cannot reach".
- **The documented install commands were run, and one of them was wrong.** `docs/INSTALL.md` verified the checksum *after* `cd`-ing into the extracted directory — but `SHA256SUMS` sits beside the archive, not inside it, so the command could not find the file it was checking. The order is now the one that was actually tested end to end: `sha256sum -c` → `tar xzf` → `cd` → run. The README install block follows the same order.
- **The product page is reachable from inside the product.** The message you get when a free-edition limit is reached, and the export error when a format is not in your edition, now say where the paid editions are. The dashboard prints the URL as plain text rather than as a link: `TestDashboardIsSelfContained` forbids `href="http` so the dashboard keeps working air-gapped, and that test is the one that is right.
- **`docs/CONCEPTS.md`** — what an assessment is claiming, what the surface map does and does not prove, and why "assessed and nothing found" and "not assessed" are drawn differently.
- Licence details in `assets.go` match the editions that are actually sold.
- The README states the pricing rule plainly: Whop sells paid licences only; the free build is downloaded here.
- CI runs `gofmt`, `go vet` and `go test` on every push.

## 0.3.0 — 2026-08-27

Seeing the surface. Every assessment produces a map of what was found where: each declared target, each host observed beneath it, each service a check actually reached. In the report as a printed tree (inline SVG, no JavaScript, prints to PDF and reads the same in black and white); in the dashboard as the Surface Explorer, the same graph in 3D on a plain 2D canvas with a hand-rolled perspective projection — no WebGL, no 3D library, no third-party code. Included in the free edition. The Change Report gained an assessment timeline, host by run, in which "assessed and nothing found" and "not assessed" get different colours *and* different shapes, because they look alike in a naive heatmap and mean opposite things.
