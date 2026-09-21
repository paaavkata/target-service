// Package service implements the business logic for target-service.
// This file previously owned the hardened HTTP client used for
// ownership-verification fetches (verifyHTTPFile / verifyMetaTag). Those
// requests are made from the platform pod to an attacker-supplied host BEFORE
// ownership is proven, so the client must be SSRF-proof:
//
//  1. Redirects are REFUSED (not silently swallowed with ErrUseLastResponse):
//     a host that answers the verification fetch with a 3xx fails verification
//     outright.
//
//  2. The reserved-IP denylist is enforced AT DIAL TIME, i.e. against the
//     ALREADY-RESOLVED connect address. Checking there (rather than pre-vetting
//     the hostname) closes the DNS-rebinding TOCTOU window and blocks direct
//     internal targets (169.254.169.254, RFC1918, pod network, IPv6 ULA, ...).
//
// Both halves now live in github.com/paaavkata/go-safedial
// (safedial.NewVerificationHTTPClient) — the single source of truth shared
// with scan-service and agent-service. verification_service.go calls it
// directly; safeDialControl is kept here only as a package-level alias so the
// existing white-box tests in safe_http_client_test.go stay verbatim.
package service

import "github.com/paaavkata/go-safedial"

// safeDialControl is the net.Dialer.Control hook that safedial.NewVerificationHTTPClient
// installs internally (denylist enforced against the resolved dial address, no
// pinning — AllowUnpinned mode). Exposed here purely so the existing dial-guard
// unit tests keep exercising the exact guard the verification client uses.
var safeDialControl = safedial.NewDialer(safedial.Config{AllowUnpinned: true}).Control
