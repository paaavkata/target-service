// Package service — this file owns the pure grading logic for the free
// security-headers-checker tool. GradeHeaders takes an already-fetched
// http.Header (no network I/O here) so it is directly unit-testable.
package service

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"target-service/internal/model"
)

// checkedHeaders is the ordered set of headers the free tool grades — must
// match the HEADERS_INFO list on scantinel-website's security-headers-checker page.
var checkedHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permissions-Policy",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Resource-Policy",
}

// GradeHeaders inspects h for the checked security headers and returns a
// verdict per header plus an overall letter grade (A-F). Pure — safe to unit
// test with a synthetic http.Header.
func GradeHeaders(h http.Header) ([]model.HeaderResult, string) {
	results := make([]model.HeaderResult, 0, len(checkedHeaders))
	score, max := 0, 0
	for _, name := range checkedHeaders {
		res := gradeOneHeader(name, h.Get(name))
		results = append(results, res)
		max += 2
		switch res.Status {
		case model.HeaderStatusPass:
			score += 2
		case model.HeaderStatusWarn:
			score += 1
		}
	}
	return results, letterGrade(score, max)
}

func gradeOneHeader(name, value string) model.HeaderResult {
	if strings.TrimSpace(value) == "" {
		return model.HeaderResult{Name: name, Status: model.HeaderStatusFail, Advice: missingAdvice(name)}
	}
	switch name {
	case "Content-Security-Policy":
		return gradeCSP(value)
	case "Strict-Transport-Security":
		return gradeHSTS(value)
	case "X-Frame-Options":
		return gradeXFO(value)
	case "X-Content-Type-Options":
		return gradeXCTO(value)
	case "Referrer-Policy":
		return gradeReferrerPolicy(value)
	case "Permissions-Policy":
		return model.HeaderResult{
			Name: name, Status: model.HeaderStatusPass, Value: value,
			Advice: "Present — review the allowed feature list matches what your site actually needs.",
		}
	case "Cross-Origin-Opener-Policy":
		return gradeCOOP(value)
	case "Cross-Origin-Resource-Policy":
		return gradeCORP(value)
	default:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value}
	}
}

func gradeCSP(value string) model.HeaderResult {
	lv := strings.ToLower(value)
	switch {
	case strings.Contains(lv, "unsafe-inline") || strings.Contains(lv, "unsafe-eval"):
		return model.HeaderResult{
			Name: "Content-Security-Policy", Status: model.HeaderStatusWarn, Value: value,
			Advice: "Contains 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protection. Use nonces or hashes for inline scripts instead.",
		}
	case strings.Contains(lv, "default-src *") || strings.Contains(lv, "default-src: *") || strings.Contains(lv, "script-src *"):
		return model.HeaderResult{
			Name: "Content-Security-Policy", Status: model.HeaderStatusWarn, Value: value,
			Advice: "Uses a wildcard source ('*'), which allows loading from any origin. Restrict to the specific domains you trust.",
		}
	default:
		return model.HeaderResult{Name: "Content-Security-Policy", Status: model.HeaderStatusPass, Value: value, Advice: "Present and does not use unsafe-inline/unsafe-eval or a wildcard source."}
	}
}

func gradeHSTS(value string) model.HeaderResult {
	const name = "Strict-Transport-Security"
	maxAge := parseHSTSMaxAge(value)
	includeSub := strings.Contains(strings.ToLower(value), "includesubdomains")
	switch {
	case maxAge <= 0:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: "max-age is missing or zero — set max-age to at least 15552000 (180 days), e.g. `max-age=31536000; includeSubDomains`."}
	case maxAge < 15552000: // 180 days
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: fmt.Sprintf("max-age=%d is short — raise it to at least 15552000 (180 days), ideally 31536000 (1 year).", maxAge)}
	case !includeSub:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: "Add includeSubDomains so subdomains are also forced to HTTPS."}
	default:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value, Advice: "Strong max-age with includeSubDomains."}
	}
}

func parseHSTSMaxAge(value string) int {
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "max-age=") {
			n, err := strconv.Atoi(strings.TrimPrefix(part, part[:8]))
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func gradeXFO(value string) model.HeaderResult {
	const name = "X-Frame-Options"
	uv := strings.ToUpper(strings.TrimSpace(value))
	switch uv {
	case "DENY", "SAMEORIGIN":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value, Advice: "Clickjacking protection is enabled."}
	default:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: "Use DENY or SAMEORIGIN (ALLOW-FROM is obsolete and ignored by modern browsers)."}
	}
}

func gradeXCTO(value string) model.HeaderResult {
	const name = "X-Content-Type-Options"
	if strings.EqualFold(strings.TrimSpace(value), "nosniff") {
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value, Advice: "Correctly set to nosniff."}
	}
	return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: `Set to exactly "nosniff" — no other value is meaningful.`}
}

func gradeReferrerPolicy(value string) model.HeaderResult {
	const name = "Referrer-Policy"
	lv := strings.ToLower(strings.TrimSpace(value))
	switch lv {
	case "no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value, Advice: "Limits referrer leakage to other origins."}
	case "unsafe-url":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusFail, Value: value, Advice: `"unsafe-url" leaks the full URL (including query strings) to every destination, even over plain HTTP. Use "strict-origin-when-cross-origin" instead.`}
	default:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: `Consider "strict-origin-when-cross-origin" for the best balance of privacy and compatibility.`}
	}
}

func gradeCOOP(value string) model.HeaderResult {
	const name = "Cross-Origin-Opener-Policy"
	lv := strings.ToLower(strings.TrimSpace(value))
	switch lv {
	case "same-origin":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value, Advice: "Isolates your window from cross-origin popups/openers."}
	case "same-origin-allow-popups":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: `"same-origin-allow-popups" is weaker than "same-origin" — use it only if you need window.open() interop.`}
	default:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: `Prefer "same-origin" unless you have a specific cross-origin popup requirement.`}
	}
}

func gradeCORP(value string) model.HeaderResult {
	const name = "Cross-Origin-Resource-Policy"
	lv := strings.ToLower(strings.TrimSpace(value))
	switch lv {
	case "same-origin", "same-site":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusPass, Value: value, Advice: "Restricts which origins can load this resource."}
	case "cross-origin":
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: `"cross-origin" allows any site to load this resource — use "same-origin" or "same-site" unless you intentionally serve public assets cross-origin.`}
	default:
		return model.HeaderResult{Name: name, Status: model.HeaderStatusWarn, Value: value, Advice: `Unrecognized value — use "same-origin", "same-site", or "cross-origin".`}
	}
}

// missingAdvice is the one-line fix shown when a checked header is absent.
func missingAdvice(name string) string {
	switch name {
	case "Content-Security-Policy":
		return "Missing. Add a Content-Security-Policy to restrict which sources can load scripts/styles/resources and mitigate XSS, e.g. `default-src 'self'`."
	case "Strict-Transport-Security":
		return "Missing. Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to force HTTPS and prevent SSL-stripping."
	case "X-Frame-Options":
		return "Missing. Add `X-Frame-Options: SAMEORIGIN` (or DENY) to prevent clickjacking via iframe embedding."
	case "X-Content-Type-Options":
		return "Missing. Add `X-Content-Type-Options: nosniff` to stop browsers from MIME-sniffing responses."
	case "Referrer-Policy":
		return "Missing. Add `Referrer-Policy: strict-origin-when-cross-origin` to limit how much referrer data leaks to other sites."
	case "Permissions-Policy":
		return "Missing. Add a Permissions-Policy to explicitly disable browser features you don't use, e.g. `camera=(), microphone=(), geolocation=()`."
	case "Cross-Origin-Opener-Policy":
		return "Missing. Add `Cross-Origin-Opener-Policy: same-origin` to isolate your window from cross-origin popups."
	case "Cross-Origin-Resource-Policy":
		return "Missing. Add `Cross-Origin-Resource-Policy: same-origin` to prevent other sites from loading your resources cross-origin."
	default:
		return "Missing."
	}
}

// letterGrade converts a score/max fraction into an A-F letter grade.
func letterGrade(score, max int) string {
	if max <= 0 {
		return "F"
	}
	pct := score * 100 / max
	return letterGradeFromPercent(pct)
}

func letterGradeFromPercent(pct int) string {
	switch {
	case pct >= 90:
		return "A"
	case pct >= 80:
		return "B"
	case pct >= 70:
		return "C"
	case pct >= 60:
		return "D"
	default:
		return "F"
	}
}
