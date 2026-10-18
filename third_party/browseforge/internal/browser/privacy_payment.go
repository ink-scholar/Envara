package browser

import (
	"net/url"
	"strings"
)

// Preserve named payment SDK services, including their fraud-prevention and
// diagnostic requests. The built-in tracker tiers still take precedence;
// unrelated advertising and analytics are not payment compatibility rules.
func paymentServiceExempt(target *url.URL) bool {
	if target == nil || target.Scheme != "https" || target.User != nil {
		return false
	}
	hostname := strings.ToLower(target.Hostname())
	authority := strings.ToLower(target.Host)
	// Accept the default HTTPS origin only, including an explicit :443. This
	// also rejects empty/noncanonical ports and bracketed non-IP hostnames.
	if authority != hostname && authority != hostname+":443" {
		return false
	}
	host := strings.TrimSuffix(hostname, ".")
	switch host {
	// Exact Stripe service hosts from https://docs.stripe.com/ips#stripe-domains.
	case "api.stripe.com", "merchant-ui-api.stripe.com", "checkout.stripe.com", "hooks.stripe.com",
		"m.stripe.com", "r.stripe.com", "q.stripe.com", "m.stripe.network", "js.stripe.com":
		return true
	// Stripe.js reports SDK/Elements errors through this separate origin:
	// https://js.stripe.com/v3/ (not the published network-origin table above).
	case "errors.stripe.com":
		return true
	// The SDK explicitly includes this endpoint in its required CSP origins:
	// https://braintree.github.io/braintree-web/current/#content-security-policy
	case "client-analytics.braintreegateway.com":
		return true
	// The PayPal SDK logger is shared by checkout and vault flows. Other paths
	// on these hosts retain their original tracker rules.
	// https://github.com/paypal/paypal-sdk-client/blob/main/src/config.js
	case "www.paypal.com", "www.sandbox.paypal.com":
		return paymentSDKPath(target, "/xoplatform/logger/api/logger", false)
	// Adyen uses this versioned endpoint for checkoutAttemptId and SDK events.
	// https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/core/Environment/constants.ts
	// https://github.com/Adyen/adyen-web/blob/main/packages/lib/src/core/Analytics/AnalyticsService.ts
	case "checkoutanalytics-test.adyen.com", "checkoutanalytics-live.adyen.com", "checkoutanalytics-live-us.adyen.com",
		"checkoutanalytics-live-au.adyen.com", "checkoutanalytics-live-apse.adyen.com", "checkoutanalytics-live-in.adyen.com",
		"checkoutanalytics-live-nea.adyen.com":
		return paymentSDKPath(target, "/checkoutanalytics/v3/analytics", true)
	}
	// Only Stripe.js explicitly requires child origins for scripts and frames.
	// Do not extend this suffix exception to all of stripe.com.
	// https://docs.stripe.com/security/guide#content-security-policy
	prefix, child := strings.CutSuffix(host, ".js.stripe.com")
	if !child || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(prefix, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
				return false
			}
		}
	}
	return true
}

func paymentSDKPath(target *url.URL, endpoint string, attemptID bool) bool {
	requestPath := strings.TrimSuffix(target.EscapedPath(), "/")
	if requestPath == endpoint {
		return true
	}
	if !attemptID {
		return false
	}
	id, child := strings.CutPrefix(requestPath, endpoint+"/")
	if !child || id == "" {
		return false
	}
	// A checkoutAttemptId occupies one URL-safe segment. Encoded separators,
	// traversal and arbitrary nested endpoints do not inherit the exception.
	for _, character := range id {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return true
}
