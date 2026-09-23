# AuditLight — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 6 September 2026*

---

## Running the tools is the easy part
Anyone can run six command-line security tools against a server. Each one prints something different, in a different format, with a different idea of what "high severity" means.
The hard part comes afterwards, and it comes twice.
First: turning six piles of output into one document a client, a manager or an auditor will actually accept — and doing that without one of the tools accidentally knocking a production system over.
Second, three months later: proving the fixes held. Not "we ran it again and it looks fine", but a list of exactly which problems are gone, which are new, and which one quietly came back.
AuditLight exists for those two moments.
## What "assessment" means here, and what it does not
Two different jobs get called the same thing. A security assessment is a systematic check for known kinds of weakness — open services, weak encryption, missing protections, credentials left lying around; it answers "what is exposed?". A penetration test is a human deliberately trying to break in, chaining weaknesses together with creativity; it answers "could someone actually get in?".
AuditLight is the first, and it says so plainly. It does not pretend to be the second. A tool that finds the recurring, mechanical problems reliably is worth a great deal; a tool that claims to replace a thinking tester is lying.
## The promise that shapes everything: it never attacks
Most assessment tooling has an "aggressive" setting somewhere. AuditLight does not, and it cannot be given one.
It detects. It never attempts exploitation, never brute-forces a password, never floods a service, never fuzzes. That is a permanent boundary built into the product, not a default you could flip — even when AuditLight hands work to an external tool like nmap, it strips out the intrusive options first.
Why this matters more than it sounds: it means AuditLight is safe to run against production. The assessment that is safe to run is the one that actually gets run.
## The report nobody gives you: what did not happen
Here is a quiet failure that happens constantly. A check could not run — a target was unreachable, a tool was missing, a timeout hit — and the report simply shows nothing for it. Nothing found looks exactly like nothing checked.
AuditLight produces three reports, and the one that makes it different is the Process Report: every check attempted, every check skipped, and why it was skipped. If nmap was not installed, the report says the deeper service detection did not run. If a target timed out, the report says so.
A check that never ran must never read as a check that passed. That sentence is the reason the Process Report exists.
## The second moment: proving the fixes held
Save an assessment. Run it again in three months. AuditLight compares the two — not by matching text, but by matching the identity of each finding (which target, which port, which condition) — and sorts every finding into exactly one of five boxes:
new · regressed · persisting · improved · resolved
That list is the Change Report, and it is the document you hand to a client who asks whether the money they spent on fixes did anything.
One honest wrinkle is written into the product: "no longer detected" is not the same as "fixed." A finding also vanishes when the check that produced it could not run. The Change Report flags this, and the Process Report tells you which case it was. Read both before telling anyone something is remediated.
## Permission that expires
Every assessment starts with a recorded authorisation — who gave permission to test what. That statement is printed in the report as evidence of due diligence.
For scheduled, recurring assessments, that permission expires after 90 days. When it lapses, the schedule stops and says so, and a human has to renew it. This is deliberate: a permission that never expires is not a permission, it is a checkbox someone clicked once.
## Why it runs with nothing else installed
AuditLight is one binary built entirely on Go's standard library. It links no third-party code, needs no database, no container, no agent, and no internet — it runs on an air-gapped host, and the reports it writes are self-contained files that open anywhere.
If you have nuclei, testssl.sh, lynis or nmap installed, AuditLight will use them in their safe modes and credit the extra coverage in the report. If you do not, everything still works. nmap is never bundled — its licence forbids it — so it stays strictly bring-your-own.
## What it will not tell you
- Whether a weakness is actually exploitable — findings are marked confirmed, likely or potential, and likely usually rests on a version string, which distributions patch without changing
- Anything behind a login
- Anything that happens between two assessments — this is change tracking, not monitoring
Every finding carries its evidence, so you can check the claim rather than trust it.
## Try it
The free Apache-2.0 edition on GitHub runs all nine checks on up to three targets, showing 50 findings, with the full Process Report and a watermarked preview of the Assessment Report.
```
curl -LO https://github.com/nizartuanku/auditlight/releases/latest/download/auditlight-free-0.3.1-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/auditlight/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf auditlight-free-0.3.1-linux-amd64.tar.gz
cd auditlight-0.3.1
./auditlight
```
Run the perimeter profile against a domain you own, and read the Process Report first. Pro and Team — the full Assessment Report and change tracking over time — are on Whop.
Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/auditlight

## Terms used above

- Security assessment — a systematic check of a system for known kinds of weakness: open services, weak encryption, missing protections, credentials left lying around. It answers "what is exposed?"
- Penetration test — a human deliberately trying to break in, chaining weaknesses together with creativity. It answers "could someone actually get in?"
