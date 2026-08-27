package adapters

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nizartuanku/auditlight/internal/finding"
)

// DNSEmail audits the DNS records that govern whether someone can send mail as
// you, and whether mail to you is protected in transit.
//
// Every lookup here reads public records. Nothing is sent to a mail server.
type DNSEmail struct{}

func (*DNSEmail) Name() string { return "dnsemail" }
func (*DNSEmail) Kind() Kind   { return KindNative }
func (*DNSEmail) Stage() Stage { return StageService }
func (*DNSEmail) Describe() string {
	return "Audits SPF, DKIM, DMARC, MTA-STS and related DNS records."
}
func (*DNSEmail) Available() (bool, string) { return true, "" }

// commonDKIMSelectors covers the selectors used by the major senders. Absence
// here is not proof that DKIM is unconfigured, and the finding says so.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "k2",
	"mail", "dkim", "s1", "s2", "zoho", "mandrill", "everlytickey1",
}

func (a *DNSEmail) Run(ctx context.Context, t Target, p Policy, _ []*finding.Finding) (Result, error) {
	var res Result
	domain := t.Host
	if domain == "" || net.ParseIP(domain) != nil {
		res.Notes = append(res.Notes, "email posture checks need a domain name, not an IP address")
		return res, nil
	}

	r := &net.Resolver{}
	tctx, cancel := context.WithTimeout(ctx, p.Timeout*3)
	defer cancel()

	mx, mxErr := r.LookupMX(tctx, domain)
	hasMail := mxErr == nil && len(mx) > 0

	// --- SPF ---------------------------------------------------------------
	txts, txtErr := r.LookupTXT(tctx, domain)
	if txtErr != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("TXT lookup for %s failed: %s", domain, condense(txtErr.Error())))
	}
	var spf string
	for _, s := range txts {
		if strings.HasPrefix(strings.ToLower(s), "v=spf1") {
			spf = s
			break
		}
	}
	switch {
	case spf == "":
		sev := finding.SeverityMedium
		if !hasMail {
			sev = finding.SeverityLow
		}
		f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, sev, finding.ConfidenceConfirmed,
			"spf-missing", "No SPF record published",
			"There is no SPF record for this domain, so receiving servers have nothing that tells them which hosts may send mail as you. That makes spoofing your domain cheap.",
			a.Name())
		f.Remediation = "Publish an SPF record listing your legitimate senders, ending in `-all` once you are confident the list is complete."
		res.Findings = append(res.Findings, f)
	default:
		f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityInfo,
			finding.ConfidenceConfirmed, "spf-present", "SPF record published",
			"An SPF record is published for this domain.", a.Name())
		f.Status = finding.StatusInformational
		f.AddEvidence("record", "SPF", spf)
		res.Findings = append(res.Findings, f)

		lower := strings.ToLower(spf)
		switch {
		case strings.Contains(lower, "+all"):
			g := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityHigh,
				finding.ConfidenceConfirmed, "spf-plusall", "SPF record ends in +all",
				"The SPF record ends in `+all`, which tells receivers that any host on the internet is authorised to send mail as this domain. That is worse than publishing nothing, because it looks like a policy.",
				a.Name())
			g.Remediation = "Replace `+all` with `-all`, or `~all` while you verify your sender list."
			g.AddEvidence("record", "SPF", spf)
			res.Findings = append(res.Findings, g)
		case strings.Contains(lower, "?all"):
			g := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityMedium,
				finding.ConfidenceConfirmed, "spf-neutral", "SPF policy is neutral",
				"The SPF record ends in `?all`, which expresses no opinion about unauthorised senders. Receivers will treat spoofed mail as neither pass nor fail.",
				a.Name())
			g.Remediation = "Move to `~all`, then to `-all` once your sender inventory is complete."
			g.AddEvidence("record", "SPF", spf)
			res.Findings = append(res.Findings, g)
		case !strings.Contains(lower, "-all") && !strings.Contains(lower, "~all"):
			g := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityLow,
				finding.ConfidenceLikely, "spf-noall", "SPF record has no terminating `all` mechanism",
				"The SPF record does not end in an `all` mechanism, so behaviour for unlisted senders is left to the receiver.",
				a.Name())
			g.Remediation = "Terminate the record with `~all` or `-all`."
			g.AddEvidence("record", "SPF", spf)
			res.Findings = append(res.Findings, g)
		}
		if n := strings.Count(lower, "include:"); n > 10 {
			g := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityLow,
				finding.ConfidenceLikely, "spf-lookups", "SPF record may exceed the DNS lookup limit",
				fmt.Sprintf("The record contains %d `include:` mechanisms. SPF permits ten DNS lookups in total; beyond that receivers must return permerror, and evaluation stops being reliable.", n),
				a.Name())
			g.Remediation = "Flatten or consolidate includes to stay within ten lookups."
			g.AddEvidence("record", "SPF", spf)
			res.Findings = append(res.Findings, g)
		}
	}

	// --- DMARC -------------------------------------------------------------
	dmarcTxt, dErr := r.LookupTXT(tctx, "_dmarc."+domain)
	var dmarc string
	for _, s := range dmarcTxt {
		if strings.HasPrefix(strings.ToLower(s), "v=dmarc1") {
			dmarc = s
			break
		}
	}
	if dErr != nil && dmarc == "" {
		sev := finding.SeverityMedium
		if !hasMail {
			sev = finding.SeverityLow
		}
		f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, sev, finding.ConfidenceConfirmed,
			"dmarc-missing", "No DMARC record published",
			"There is no DMARC policy at `_dmarc` for this domain. Without one, SPF and DKIM results are advisory: receivers have no instruction about what to do when checks fail, and you receive no reports about who is sending as you.",
			a.Name())
		f.Remediation = "Publish `v=DMARC1; p=none; rua=mailto:you@example.com` first to collect reports, then tighten to quarantine and reject."
		res.Findings = append(res.Findings, f)
	} else if dmarc != "" {
		policy := dmarcTag(dmarc, "p")
		f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityInfo,
			finding.ConfidenceConfirmed, "dmarc-present", "DMARC record published",
			fmt.Sprintf("A DMARC record is published with policy %q.", policy), a.Name())
		f.Status = finding.StatusInformational
		f.AddEvidence("record", "DMARC", dmarc)
		res.Findings = append(res.Findings, f)

		if policy == "none" || policy == "" {
			g := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityMedium,
				finding.ConfidenceConfirmed, "dmarc-none", "DMARC policy is monitoring only",
				"The DMARC policy is `p=none`, which asks receivers to report but not to act. Mail that fails authentication is still delivered, so the domain remains spoofable.",
				a.Name())
			g.Remediation = "Once reports show your legitimate senders pass, move to `p=quarantine` and then `p=reject`."
			g.AddEvidence("record", "DMARC", dmarc)
			res.Findings = append(res.Findings, g)
		}
		if dmarcTag(dmarc, "rua") == "" {
			g := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityLow,
				finding.ConfidenceConfirmed, "dmarc-norua", "DMARC record requests no aggregate reports",
				"No `rua` address is set, so no aggregate reports are collected. Without them there is no way to see who is sending as your domain, and no safe path to a stricter policy.",
				a.Name())
			g.Remediation = "Add an `rua=mailto:` address and review the reports."
			g.AddEvidence("record", "DMARC", dmarc)
			res.Findings = append(res.Findings, g)
		}
	}

	// --- DKIM --------------------------------------------------------------
	if hasMail {
		var found []string
		for _, sel := range commonDKIMSelectors {
			recs, err := r.LookupTXT(tctx, sel+"._domainkey."+domain)
			if err == nil && len(recs) > 0 {
				found = append(found, sel)
			}
		}
		if len(found) == 0 {
			f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityLow,
				finding.ConfidencePotential, "dkim-none-common", "No DKIM key found at common selectors",
				fmt.Sprintf("None of %d commonly used DKIM selectors resolved for this domain. DKIM selectors are arbitrary, so this is not proof that DKIM is unconfigured — it means it could not be confirmed from outside.", len(commonDKIMSelectors)),
				a.Name())
			f.Status = finding.StatusManualReview
			f.Remediation = "Confirm with your mail provider which selector is in use, and verify the key resolves."
			f.AddEvidence("lookup", "selectors tried", strings.Join(commonDKIMSelectors, ", "))
			res.Findings = append(res.Findings, f)
		} else {
			f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityInfo,
				finding.ConfidenceConfirmed, "dkim-present", "DKIM key published",
				"A DKIM public key was found at a common selector.", a.Name())
			f.Status = finding.StatusInformational
			f.AddEvidence("record", "selectors", strings.Join(found, ", "))
			res.Findings = append(res.Findings, f)
		}

		// MTA-STS
		if _, err := r.LookupTXT(tctx, "_mta-sts."+domain); err != nil {
			f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityLow,
				finding.ConfidenceConfirmed, "mta-sts-missing", "No MTA-STS policy published",
				"There is no MTA-STS record. Without it, a sending server that cannot negotiate TLS with your mail host will quietly fall back to plain text rather than refuse.",
				a.Name())
			f.Remediation = "Publish an MTA-STS policy and the matching `_mta-sts` TXT record, starting in testing mode."
			res.Findings = append(res.Findings, f)
		}
	}

	// --- Inventory ---------------------------------------------------------
	if hasMail {
		var hosts []string
		for _, m := range mx {
			hosts = append(hosts, fmt.Sprintf("%s (pref %d)", strings.TrimSuffix(m.Host, "."), m.Pref))
		}
		f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityInfo,
			finding.ConfidenceConfirmed, "mx-inventory", "Mail exchangers",
			"The mail hosts this domain publishes.", a.Name())
		f.Status = finding.StatusInformational
		f.AddEvidence("record", "MX", strings.Join(hosts, ", "))
		res.Findings = append(res.Findings, f)
	} else {
		res.Notes = append(res.Notes, "domain publishes no MX record; mail-specific checks were limited")
	}

	if ns, err := r.LookupNS(tctx, domain); err == nil && len(ns) > 0 {
		var hosts []string
		for _, n := range ns {
			hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
		}
		f := finding.New(t.Raw, 0, finding.CategoryDNSEmail, finding.SeverityInfo,
			finding.ConfidenceConfirmed, "ns-inventory", "Authoritative name servers",
			"The name servers authoritative for this domain.", a.Name())
		f.Status = finding.StatusInformational
		f.AddEvidence("record", "NS", strings.Join(sortedStrings(hosts), ", "))
		res.Findings = append(res.Findings, f)
	}

	return res, nil
}

// dmarcTag extracts a tag value from a DMARC record.
func dmarcTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), tag+"=") {
			return strings.ToLower(strings.TrimSpace(part[len(tag)+1:]))
		}
	}
	return ""
}

// Subdomain enumerates subdomains by resolving names from an embedded wordlist.
//
// The list is short and deliberate. Exhaustive brute force is slow, noisy, and
// rarely changes an audit's conclusion; the names here are the ones that
// actually turn up forgotten hosts.
type Subdomain struct{}

func (*Subdomain) Name() string { return "subdomain" }
func (*Subdomain) Kind() Kind   { return KindNative }
func (*Subdomain) Stage() Stage { return StageDiscovery }
func (*Subdomain) Describe() string {
	return "Resolves an embedded list of common subdomain names to find forgotten hosts."
}
func (*Subdomain) Available() (bool, string) { return true, "" }

var subdomainWords = []string{
	"www", "mail", "webmail", "smtp", "imap", "pop", "ns1", "ns2",
	"vpn", "remote", "portal", "admin", "administrator", "cpanel", "whm",
	"dev", "development", "staging", "stage", "test", "testing", "uat", "qa",
	"demo", "beta", "preprod", "sandbox",
	"api", "api-dev", "app", "apps", "mobile", "m",
	"git", "gitlab", "jenkins", "ci", "build", "nexus", "registry",
	"jira", "confluence", "wiki", "docs", "support", "help", "status",
	"db", "database", "mysql", "postgres", "redis", "mongo",
	"backup", "backups", "old", "legacy", "archive", "temp",
	"monitor", "monitoring", "grafana", "kibana", "prometheus", "nagios",
	"intranet", "internal", "corp", "office", "files", "ftp", "sftp",
	"cdn", "static", "assets", "media", "img", "images",
	"secure", "login", "sso", "auth", "id", "account",
	"shop", "store", "pay", "payment", "billing", "invoice",
	"blog", "news", "forum", "community",
}

func (a *Subdomain) Run(ctx context.Context, t Target, p Policy, _ []*finding.Finding) (Result, error) {
	var res Result
	domain := t.Host
	if domain == "" || net.ParseIP(domain) != nil {
		res.Notes = append(res.Notes, "subdomain enumeration needs a domain name, not an IP address")
		return res, nil
	}
	// Enumerate against the registrable-looking parent, so that a target of
	// www.example.com still discovers its siblings.
	if labels := strings.Split(domain, "."); len(labels) > 2 {
		domain = strings.Join(labels[len(labels)-2:], ".")
	}

	r := &net.Resolver{}

	// A wildcard record makes every name resolve, which would otherwise produce
	// a page of meaningless findings. Detect it and say so instead.
	probe := fmt.Sprintf("auditlight-wildcard-probe-%d.%s", time.Now().UnixNano()%1e6, domain)
	if addrs, err := r.LookupHost(ctx, probe); err == nil && len(addrs) > 0 {
		f := finding.New(t.Raw, 0, finding.CategoryDiscovery, finding.SeverityInfo,
			finding.ConfidenceConfirmed, "dns-wildcard", "DNS wildcard record in use",
			"A randomly generated name resolved, so this domain answers for names that do not exist. Subdomain enumeration cannot distinguish real hosts here and was skipped.",
			a.Name())
		f.Status = finding.StatusInformational
		f.AddEvidence("lookup", "wildcard probe", fmt.Sprintf("%s resolved to %s", probe, strings.Join(addrs, ", ")))
		res.Findings = append(res.Findings, f)
		res.Notes = append(res.Notes, "subdomain enumeration skipped: wildcard DNS in use")
		return res, nil
	}

	words := subdomainWords
	if p.MaxSubdomains > 0 && len(words) > p.MaxSubdomains {
		words = words[:p.MaxSubdomains]
		res.Notes = append(res.Notes, fmt.Sprintf("subdomain wordlist limited to %d of %d names by policy", len(words), len(subdomainWords)))
	}

	type hit struct {
		name  string
		addrs []string
	}
	var (
		mu   sync.Mutex
		hits []hit
	)
	sem := make(chan struct{}, max(1, p.Concurrency))
	var wg sync.WaitGroup
	for _, w := range words {
		select {
		case <-ctx.Done():
			wg.Wait()
			res.Notes = append(res.Notes, "subdomain enumeration stopped early: "+ctx.Err().Error())
			return res, nil
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			name := w + "." + domain
			lctx, cancel := context.WithTimeout(ctx, p.DialTimeout)
			defer cancel()
			addrs, err := r.LookupHost(lctx, name)
			if err != nil || len(addrs) == 0 {
				return
			}
			mu.Lock()
			hits = append(hits, hit{name: name, addrs: addrs})
			mu.Unlock()
		}(w)
	}
	wg.Wait()

	for _, h := range hits {
		sev := finding.SeverityInfo
		status := finding.StatusInformational
		desc := fmt.Sprintf("The name %s resolves. Recording it keeps the asset inventory honest: hosts nobody remembers are the ones that stop being patched.", h.name)
		if interestingSubdomain(h.name) {
			sev = finding.SeverityLow
			status = finding.StatusOpen
			desc = fmt.Sprintf("The name %s resolves. Names like this usually front non-production or administrative systems, which tend to be less hardened than production yet just as reachable.", h.name)
		}
		// The subject of this finding is the host that was discovered, not the
		// domain it was discovered from. Filing it under the parent made the
		// finding read correctly and the surface map read wrongly — the host
		// had been observed, and nothing in the model said so. The signature
		// still names the parent, so identity stays stable across runs.
		f := finding.New(h.name, 0, finding.CategoryDiscovery, sev, finding.ConfidenceConfirmed,
			"subdomain:"+t.Host, "Subdomain resolves: "+h.name, desc, a.Name())
		f.Status = status
		f.Remediation = "Confirm the host is still needed and still maintained. Retire what is not, and bring what remains into patching and monitoring."
		f.AddEvidence("lookup", h.name, strings.Join(sortedStrings(h.addrs), ", "))
		res.Findings = append(res.Findings, f)
	}
	if len(hits) == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("no subdomain resolved from %d candidate names", len(words)))
	}
	return res, nil
}

func interestingSubdomain(name string) bool {
	for _, w := range []string{
		"admin", "dev", "staging", "stage", "test", "uat", "qa", "demo",
		"beta", "preprod", "sandbox", "old", "legacy", "backup", "temp",
		"internal", "intranet", "jenkins", "gitlab", "grafana", "kibana",
		"cpanel", "whm", "phpmyadmin",
	} {
		if strings.HasPrefix(name, w+".") || strings.Contains(name, "."+w+".") {
			return true
		}
	}
	return false
}
