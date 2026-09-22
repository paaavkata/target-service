// Package service — this file owns the free email-authentication tool
// (SPF/DMARC/DKIM). The parsers (ParseSPF, ParseDMARC) are pure — no DNS —
// so they are unit-testable directly; EmailAuthChecker does the DNS I/O via
// the system resolver (read-only TXT lookups, no outbound HTTP to the
// customer host, so no go-safedial client is needed here).
package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"target-service/internal/model"
	"time"
)

// dkimSelectors are the common DKIM selector names probed by the free tool.
var dkimSelectors = []string{"google", "selector1", "selector2", "default", "mail", "dkim", "k1", "s1", "s2"}

// txtResolver abstracts net.Resolver.LookupTXT so DNS is injectable in tests.
type txtResolver interface {
	LookupTXT(ctx context.Context, host string) ([]string, error)
}

// EmailAuthChecker runs the SPF/DMARC/DKIM DNS lookups for a domain.
type EmailAuthChecker struct {
	resolver txtResolver
}

// NewEmailAuthChecker builds a checker using the system DNS resolver.
func NewEmailAuthChecker() *EmailAuthChecker {
	return &EmailAuthChecker{resolver: net.DefaultResolver}
}

// Check runs the SPF, DMARC and common-selector DKIM lookups for domain.
func (c *EmailAuthChecker) Check(ctx context.Context, domain string) (*model.EmailAuthResponse, error) {
	resp := &model.EmailAuthResponse{Domain: domain, CheckedAt: time.Now().UTC()}

	spfRecords := c.lookupTXT(ctx, domain)
	resp.SPF = ParseSPF(findRecordWithPrefix(spfRecords, "v=spf1"))

	dmarcRecords := c.lookupTXT(ctx, "_dmarc."+domain)
	resp.DMARC = ParseDMARC(findRecordWithPrefix(dmarcRecords, "v=dmarc1"))

	resp.DKIM = make([]model.DKIMSelectorResult, 0, len(dkimSelectors))
	for _, sel := range dkimSelectors {
		recs := c.lookupTXT(ctx, sel+"._domainkey."+domain)
		rec := findRecordWithPrefix(recs, "v=dkim1")
		if rec == "" && len(recs) > 0 {
			rec = recs[0] // some providers publish DKIM TXT records without a v=DKIM1 tag
		}
		resp.DKIM = append(resp.DKIM, model.DKIMSelectorResult{Selector: sel, Present: rec != "", Record: rec})
	}

	resp.Fixes = buildEmailFixes(domain, resp)
	return resp, nil
}

func (c *EmailAuthChecker) lookupTXT(ctx context.Context, host string) []string {
	recs, err := c.resolver.LookupTXT(ctx, host)
	if err != nil {
		return nil
	}
	return recs
}

// findRecordWithPrefix returns the first TXT record (case-insensitive) that
// starts with prefix, joining any RFC 4408 split segments the resolver may
// return concatenated (Go's LookupTXT already de-chunks TXT strings).
func findRecordWithPrefix(records []string, prefix string) string {
	for _, r := range records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r)), prefix) {
			return strings.TrimSpace(r)
		}
	}
	return ""
}

// ParseSPF parses a raw "v=spf1 ..." TXT record. Pure — no DNS. An empty
// record means "no SPF record found".
func ParseSPF(record string) model.SPFResult {
	if strings.TrimSpace(record) == "" {
		res := model.SPFResult{Present: false}
		res.Warnings = append(res.Warnings, "No SPF record found. Without SPF, any server can send email claiming to be from your domain with no DNS-level check.")
		return res
	}
	res := model.SPFResult{Present: true, Record: record}
	lookups := 0
	qualifier := ""
	for _, f := range strings.Fields(record) {
		lf := strings.ToLower(f)
		switch {
		case lf == "-all" || lf == "~all" || lf == "?all" || lf == "+all":
			qualifier = lf
		case lf == "all":
			qualifier = "+all"
		case strings.HasPrefix(lf, "include:"), lf == "a", strings.HasPrefix(lf, "a:"), strings.HasPrefix(lf, "a/"),
			lf == "mx", strings.HasPrefix(lf, "mx:"), strings.HasPrefix(lf, "mx/"),
			lf == "ptr", strings.HasPrefix(lf, "ptr:"),
			strings.HasPrefix(lf, "exists:"), strings.HasPrefix(lf, "redirect="):
			lookups++
		}
	}
	res.LookupCount = lookups
	res.Qualifier = qualifier

	switch qualifier {
	case "":
		res.Warnings = append(res.Warnings, `No "all" mechanism found — add "-all" (or at least "~all") at the end so mail servers know what to do with senders you didn't authorize.`)
	case "+all":
		res.Warnings = append(res.Warnings, `"+all" allows ANY server to send as your domain — this defeats SPF entirely. Use "-all" or "~all".`)
	case "~all":
		res.Warnings = append(res.Warnings, `"~all" (soft fail) lets spoofed mail through with just a warning. Use "-all" (hard fail) once you've confirmed all your real senders are covered.`)
	}
	if lookups > 10 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("This SPF record costs %d DNS lookups; RFC 7208 caps SPF evaluation at 10 — mail may fail with a permerror. Flatten includes or remove unused ones.", lookups))
	}
	return res
}

// ParseDMARC parses a raw "v=DMARC1; ..." TXT record. Pure — no DNS.
func ParseDMARC(record string) model.DMARCResult {
	if strings.TrimSpace(record) == "" {
		res := model.DMARCResult{Present: false}
		res.Warnings = append(res.Warnings, "No DMARC record found at _dmarc.<domain>. Without DMARC, SPF/DKIM failures are not enforced and forged mail can still reach inboxes.")
		return res
	}
	res := model.DMARCResult{Present: true, Record: record, Policy: "none"}
	for _, tag := range strings.Split(record, ";") {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		kv := strings.SplitN(tag, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "p":
			res.Policy = strings.ToLower(val)
		case "rua":
			res.RUAPresent = val != ""
		}
	}
	switch res.Policy {
	case "none", "":
		res.Warnings = append(res.Warnings, `Policy is "p=none" — failures are only reported, not blocked. Move to "p=quarantine" and then "p=reject" once your aggregate reports look clean.`)
	case "quarantine":
		res.Warnings = append(res.Warnings, `Policy is "p=quarantine" — failing mail is sent to spam, not blocked. Consider "p=reject" once you're confident in your setup.`)
	}
	if !res.RUAPresent {
		res.Warnings = append(res.Warnings, "No rua= reporting address — add one (e.g. `rua=mailto:dmarc-reports@yourdomain.com`) so you receive DMARC aggregate reports.")
	}
	return res
}

// buildEmailFixes turns the parsed results into copy-paste-ready DNS fixes.
func buildEmailFixes(domain string, resp *model.EmailAuthResponse) []string {
	var fixes []string
	if !resp.SPF.Present {
		fixes = append(fixes, fmt.Sprintf("Add a TXT record on %s: `v=spf1 include:_spf.google.com -all` (replace the include: with your actual mail provider, then add \"-all\").", domain))
	} else {
		fixes = append(fixes, resp.SPF.Warnings...)
	}
	if !resp.DMARC.Present {
		fixes = append(fixes, fmt.Sprintf("Add a TXT record on _dmarc.%s: `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s`.", domain, domain))
	} else {
		fixes = append(fixes, resp.DMARC.Warnings...)
	}
	anyDKIM := false
	for _, d := range resp.DKIM {
		if d.Present {
			anyDKIM = true
			break
		}
	}
	if !anyDKIM {
		fixes = append(fixes, "No DKIM selector found among the common ones (google, selector1, selector2, default, mail, dkim, k1, s1, s2). Check your mail provider's DKIM setup docs for the exact selector name they issued you, and publish it as a TXT record at `<selector>._domainkey."+domain+"`.")
	}
	return fixes
}
