# AuditLight user guide

## The four steps

### 1. Scope

Choose a profile, then list what to assess — one host, domain or URL per line. Anything the
operator can type is accepted: `example.com`, `https://app.example.com/`, `192.0.2.10`,
`10.4.1.7`, `localhost`.

Auditing your own machine or an internal asset is a first-class use case, and it is the
safest thing anyone can scan. The control against scanning what you do not own is the
authorisation statement and the scope guard, not a ban on private addresses.

**Scope guard.** Optional, and worth using. Give it domains or CIDRs:

```
example.com
192.0.2.0/24
```

Any target outside them is skipped and the reason is recorded. It exists to stop the
accident where a copied-and-pasted list quietly includes somebody else's host.

### 2. Authorise

Give an operator name, accept the statement, and re-enter the target list.

The re-entry is not busywork. A checkbox is a reflex; typing the targets a second time is a
decision. Both go into a hash-chained audit log, and the Process Report prints the statement,
the operator, the timestamp and the chain hashes.

If the two lists differ in any way, the job is refused. That is deliberate.

### 3. Assess

Checks run in stages, and each stage can use what the previous one found:

1. **Discovery** — subdomain enumeration.
2. **Network** — port scan.
3. **Service** — banners, HTTP probing, TLS audit, DNS and email records, secret scanning.
4. **Derived** — security headers, version signature matching, and any external tools.

The progress panel names the check and target currently running. Every check that runs is
recorded, including the ones that fail, and including the ones that were unavailable.

### 4. Report

**Assessment Report** — the document you hand over. Executive summary, an attack surface
map, findings ranked by severity then confidence, evidence for each, remediation, control
mapping, and a methodology section that states the limits plainly.

**Process Report** — the document that makes the first one trustworthy. Authorisation
record, every check attempted with its outcome, every target processed or skipped with the
reason, the capability matrix, and the safe-mode arguments imposed on external tools.

Read them together. The Assessment Report says what was found; the Process Report says what
was looked for.

Both print to PDF from the browser without a plugin.

---

## Reading the surface

Both the report and the dashboard draw the same thing, in the shape that suits where it
appears.

**The map in the report** is a tree: declared target, then the hosts observed beneath it,
then the services a check reached, then the findings recorded against each. One row per
node, worst first. It prints.

**The Surface Explorer in the dashboard** is the same graph with the third dimension put
back. Drag to rotate, scroll to zoom, click a node to see its findings. Rotation is not
decoration — it is what separates a cluster of services that a flat drawing piles on top of
each other.

Read both the same way:

- A **host** sits under a target because its name is that target or a DNS-suffix of it.
- A **service** sits under a host because a check observed that port open.
- A node's **colour** is the worst severity recorded at or below it.
- A **skipped target** is drawn, greyed, with its reason — it is not quietly missing.
- **"+n more"** means the drawing was folded to keep the page readable. The findings it
  stands for are still counted in every total.

**What the picture is not.** It is not a network diagram. AuditLight runs no traceroute and
probes no adjacency, so it does not know which host talks to which, and it draws nothing it
did not observe. If you hand this map to a client, that sentence is worth saying out loud —
people read diagrams as authoritative far faster than they read prose.

---

## Reading a finding

**Severity** is how serious the condition is if it is real: `critical`, `high`, `medium`,
`low`, `info`.

**Confidence** is how sure AuditLight is that it is real:

- `confirmed` — observed directly. An expired certificate, a missing DMARC record, a port
  that completed a TCP handshake.
- `likely` — strong evidence with inference involved. Almost always a version string.
- `potential` — a suggestive signal, not a conclusion.

Because AuditLight never exploits anything, it can rarely prove exploitability. Confidence is
the honest expression of that limit, not a hedge.

**"N checks agree"** means more than one independent check found the same condition.
Corroboration raises confidence by one step, once per distinct check, never past `confirmed`.

**"Needs review"** means AuditLight found something it cannot classify automatically. It says
so rather than guessing.

**Evidence** is the raw observation: the banner, the header, the record, the certificate
field. It is there so you can verify a finding rather than take it on trust — and so you can
dismiss a false positive quickly.

---

## Interpreting the count

A low finding count is not a clean bill of health. It means these checks, within this scope,
detected nothing more. The Process Report tells you what was actually attempted; if half the
capability matrix was unavailable, the count reflects that too.

AuditLight will never tell you a host is secure. It will tell you what it found and what it
looked for.

---

## Tracking change over time

Save an assessment and AuditLight will re-run it and tell you what moved. This is the part
clients pay for on the second engagement: not the list of problems, but the proof that the
list got shorter.

**Saving one.** After a run completes, name it and choose a cadence. Everything else —
targets, profile, scope, operator, authorisation — is carried over from the run you just did.

**The Change Report.** Every finding from both runs lands in exactly one class:

- **new** — present now, absent before
- **regressed** — present in both, more severe now
- **persisting** — present in both, unchanged
- **improved** — present in both, less severe now
- **resolved** — present before, absent now

Plus a severity trend: how many criticals, highs and so on, before and after.

**The assessment timeline.** Once a saved assessment has run twice, the Change Report also
draws a host × run grid: every host down the side, every run across the top, coloured by the
worst severity found on that host in that run.

Look at the key before you read the grid. "Assessed, nothing found" and "not assessed" are
different colours and carry different shapes, because they mean opposite things and a
heatmap that blurs them is worse than no heatmap. A cell is grey and slashed when that host
was not assessed in that run — the target was skipped, or it had not been discovered yet.

**Read "resolved" carefully.** A finding leaves the results when the condition is gone — but
also when the check that found it did not run, or a target was skipped. The Process Report
for that run lists every check attempted and every target skipped, with reasons. Check it
before telling a client something was remediated. The Change Report says this too, in the
report itself, so a client reading it unaccompanied gets the same caveat you would give them.

**Authorisation expires.** A saved assessment carries your authorisation for 90 days by
default. When it lapses, scheduled runs stop, the reason appears on the assessment, and the
"Run now" button is replaced by "Re-affirm". This is not friction for its own sake: consent
to scan somebody's infrastructure genuinely does go stale, and a tool that keeps scanning on
a year-old checkbox is doing you no favours.

**Notifications.** Per assessment, not per finding. A webhook receives JSON; e-mail receives
a plain-text summary. Choose `change` (anything moved), `worse` (only new or regressed), or
`never`. If a notification fails to send, it is recorded on the assessment rather than
silently dropped — believing you are covered when you are not is the worst of the three
possible states.

### Comparing by hand

Finding identity is deterministic, so you can diff exports directly if you prefer:

```sh
curl -s localhost:8431/api/jobs/JOB_A/export.json | jq -r '.findings[].id' | sort > a.txt
curl -s localhost:8431/api/jobs/JOB_B/export.json | jq -r '.findings[].id' | sort > b.txt
comm -13 a.txt b.txt   # new in B
comm -23 a.txt b.txt   # resolved since A
```

Export and the Change Report are paid features.

---

## Control mapping

Paid editions map findings to ISO 27001:2022 Annex A, CIS Controls v8, NIST CSF 2.0 and
UU PDP (UU 27/2022) by category.

This is supporting evidence for an audit. It is not a statement of compliance, not a
certification, and not a legal opinion. UU PDP in particular is principle-based rather than a
technical checklist: these findings can help demonstrate that technical measures were taken
under Pasal 35 and 36, and support breach-detection readiness under Pasal 46. Nothing more.

Say that to your client too. A report that overstates what it proves is worth less than one
that is precise about its limits.

---

## Common questions

**Will this take my production system down?**
It should not. Every check is detection only, concurrency and rate are conservative by
default, there is no aggressive mode, and the orchestrator refuses intrusive arguments even
for external tools. A connect scan and a handful of HTTP requests is a normal Tuesday for any
public service. Assess a staging copy first if you are cautious — that is always good
practice.

**Why does it report so many informational items?**
Because an asset inventory is useful. Contextual records are separated from findings in both
the report and the counts.

**A finding is wrong. What now?**
Check the evidence, then dismiss it. Version-based findings are the usual culprit:
distributions back-port fixes without changing the advertised version. This is why those
findings are capped at `likely` and say so in their own text.

**Can I run it against a client's systems?**
Only with their written authorisation. AuditLight records your statement as evidence, which
protects you — but having the authorisation is your responsibility, not the tool's.

**Is this monitoring?**
No, and the distinction matters. AuditLight compares snapshots taken weeks apart; it does not
watch anything between runs. A problem that appears and disappears in the gap is never seen.
If you need continuous watching of certificates, attack surface or DMARC, that is what the
other tools in the Hexward line do.

**Why is nmap not included?**
Its licence forbids redistribution inside a commercial product. AuditLight uses its own
connect scan by default; install nmap yourself and the adapter will use it.
