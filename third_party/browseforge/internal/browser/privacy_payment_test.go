package browser

import (
	"net/url"
	"testing"
)

func TestPaymentServicesRemainAvailableWithPrivacy(t *testing.T) {
	requests := []struct {
		url  string
		kind uint16
	}{
		{"https://js.stripe.com/v3/", kindScript},
		{"https://b.js.stripe.com/v3/elements-inner.html", kindSubdocument},
		{"https://api.stripe.com/v1/elements/sessions", kindXHR},
		{"https://api.stripe.com/v1/payment_pages/fixture/init", kindXHR},
		{"https://merchant-ui-api.stripe.com/link/get-cookie", kindXHR},
		{"https://merchant-ui-api.stripe.com/elements/wallet-config", kindXHR},
		{"https://checkout.stripe.com/c/pay/fixture", kindSubdocument},
		{"https://hooks.stripe.com/redirect/fixture", kindSubdocument},
		{"https://m.stripe.network/inner.html", kindSubdocument},
		{"https://m.stripe.com/6", kindXHR},
		{"https://r.stripe.com/b", kindPing},
		{"https://q.stripe.com/fixture", kindXHR},
		{"https://errors.stripe.com/fixture", kindXHR},
		{"https://client-analytics.braintreegateway.com/fixture", kindXHR},
		{"https://www.paypal.com/xoplatform/logger/api/logger?disableSetCookie=true", kindXHR},
		{"https://www.sandbox.paypal.com/xoplatform/logger/api/logger", kindXHR},
	}
	for _, mode := range []string{"standard", "strict"} {
		for _, firstParty := range []string{"https://claude.ai/", "https://shop.example/", ""} {
			for _, request := range requests {
				if blockTrackerRequest(request.url, firstParty, mode, request.kind) {
					t.Errorf("%s blocked payment request %s on %s", mode, request.url, firstParty)
				}
			}
			// The bundled parent-domain event rule must not reclaim a payment
			// service through another path or resource type.
			for _, target := range []string{"https://m.stripe.com/6", "https://r.stripe.com/b", "https://api.stripe.com/?event=fixture", "https://errors.stripe.com/?event=fixture", "https://b.js.stripe.com/?event=fixture"} {
				for _, kind := range []uint16{kindScript, kindImage, kindStylesheet, kindXHR, kindSubdocument, kindPing, kindMedia, kindFont, kindOther} {
					if blockTrackerRequest(target, firstParty, mode, kind) {
						t.Errorf("%s blocked payment service %s (kind %d)", mode, target, kind)
					}
				}
			}
			for _, host := range []string{"checkoutanalytics-test.adyen.com", "checkoutanalytics-live.adyen.com", "checkoutanalytics-live-us.adyen.com", "checkoutanalytics-live-au.adyen.com", "checkoutanalytics-live-apse.adyen.com", "checkoutanalytics-live-in.adyen.com", "checkoutanalytics-live-nea.adyen.com"} {
				for _, path := range []string{"/checkoutanalytics/v3/analytics?clientKey=fixture", "/checkoutanalytics/v3/analytics/attempt-fixture_42?clientKey=fixture"} {
					if blockTrackerRequest("https://"+host+path, firstParty, mode, kindXHR) {
						t.Errorf("%s blocked Adyen SDK request %s%s", mode, host, path)
					}
				}
			}
		}
	}
}

func TestPaymentExceptionRequiresNamedHTTPSOrigins(t *testing.T) {
	for _, check := range []struct {
		url  string
		want bool
	}{
		{"https://js.stripe.com/v3/", true},
		{"https://b.js.stripe.com/v3/", true},
		{"https://v3.b.js.stripe.com/frame.html", true},
		{"https://M.STRIPE.COM/6", true},
		{"https://m.stripe.com.:443/6", true},
		{"https://m.stripe.com:443/6", true},
		{"https://errors.stripe.com/?event=fixture", true},
		{"https://client-analytics.braintreegateway.com/fixture", true},
		{"https://www.paypal.com/xoplatform/logger/api/logger/", true},
		{"https://www.sandbox.paypal.com/xoplatform/logger/api/logger", true},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics/", true},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics/attempt-fixture_42/", true},
		{"http://m.stripe.com/6", false},
		{"wss://m.stripe.com/6", false},
		{"https://m.stripe.com:80/6", false},
		{"https://m.stripe.com:8443/6", false},
		{"https://m.stripe.com:0443/6", false},
		{"https://m.stripe.com:65536/6", false},
		{"https://m.stripe.com:/6", false},
		{"https://[m.stripe.com]/6", false},
		{"https://user@m.stripe.com/6", false},
		{"https://m.stripe.com@evil.example/6", false},
		{"https://m.stripe.com.evil.example/6", false},
		{"https://mstripe.com/6", false},
		{"https://events.m.stripe.com/6", false},
		{"https://api.stripe.com.evil.example/", false},
		{"https://eviljs.stripe.com/", false},
		{"https://js.stripe.com.evil.example/v3/", false},
		{"https://.js.stripe.com/v3/", false},
		{"https://foo..js.stripe.com/v3/", false},
		{"https://-foo.js.stripe.com/v3/", false},
		{"https://foo-.js.stripe.com/v3/", false},
		{"https://foo_bar.js.stripe.com/v3/", false},
		{"https://stripe.com/", false},
		{"https://telemetry.stripe.com/", false},
		{"https://stripe.network/", false},
		{"https://other.stripe.network/", false},
		{"https://pay.google.com/", false},
		{"https://a.hcaptcha.com/", false},
		{"https://statsig.anthropic.com/", false},
		{"https://example.com/?redirect=https://m.stripe.com", false},
		{"http://client-analytics.braintreegateway.com/fixture", false},
		{"https://client-analytics.braintreegateway.com:8443/fixture", false},
		{"https://client-analytics.braintreegateway.com.evil.example/fixture", false},
		{"https://events.client-analytics.braintreegateway.com/fixture", false},
		{"http://www.paypal.com/xoplatform/logger/api/logger", false},
		{"https://www.paypal.com:8443/xoplatform/logger/api/logger", false},
		{"https://www.paypal.com.evil.example/xoplatform/logger/api/logger", false},
		{"https://foo.www.paypal.com/xoplatform/logger/api/logger", false},
		{"https://www.paypal.com/xoplatform/logger/api/logger-extra", false},
		{"https://www.paypal.com/xoplatform/logger/api/logger/extra", false},
		{"https://www.paypal.com/xoplatform/logger/api/%6cogger", false},
		{"https://www.paypal.com/xoplatform/logger/api/logger//", false},
		{"https://www.paypal.com/ptrk/fixture", false},
		{"http://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics", false},
		{"https://checkoutanalytics-live.adyen.com:8443/checkoutanalytics/v3/analytics", false},
		{"https://checkoutanalytics-live.adyen.com.evil.example/checkoutanalytics/v3/analytics", false},
		{"https://checkoutanalytics-unknown.adyen.com/checkoutanalytics/v3/analytics", false},
		{"https://checkoutshopper-live.adyen.com/checkoutanalytics/v3/analytics", false},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v2/analytics", false},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics-extra", false},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics/../other", false},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics/id/extra", false},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics/id%2fextra", false},
		{"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics/%2e%2e", false},
		{"https://checkoutanalytics-live.adyen.com/other", false},
	} {
		target, err := url.Parse(check.url)
		if err != nil {
			t.Fatalf("invalid test URL %s: %v", check.url, err)
		}
		if got := paymentServiceExempt(target); got != check.want {
			t.Errorf("paymentServiceExempt(%s) = %t, want %t", check.url, got, check.want)
		}
	}
	if paymentServiceExempt(nil) {
		t.Fatal("missing URL received a payment exception")
	}
}

func TestPaymentCompatibilityPreservesTrackerRules(t *testing.T) {
	for _, mode := range []string{"standard", "strict"} {
		for _, target := range []string{
			"https://www.google-analytics.com/g/collect", "https://api.segment.io/v1/track",
			"https://a.hcaptcha.com/fixture", "https://statsig.anthropic.com/v1/fixture",
			"https://stripe.com/?event=fixture", "https://telemetry.stripe.com/?event=fixture",
			"https://events.m.stripe.com/6", "http://m.stripe.com/6", "https://m.stripe.com:8443/6",
			"https://m.stripe.com:0443/6", "https://user@m.stripe.com/6", "https://m.stripe.com:/6",
			"https://www.google-analytics.com/g/collect?redirect=https://m.stripe.com/6",
			"https://events.client-analytics.braintreegateway.com/fixture",
			"https://www.paypal.com/xoplatform/logger/api/logger-extra", "https://www.paypal.com/xoplatform/logger/api/logger/extra",
			"https://www.paypal.com/ptrk/fixture", "https://www.paypal.com/credit-presentment/glog?fixture",
			"https://www.paypal.com/webapps/mch/cmd/?fixture", "https://www.paypal.com/a/pixel.gif", "https://www.paypalobjects.com/a/pixel.gif", "https://t.paypal.com/ts?fixture",
			"https://checkoutanalytics-live.adyen.com/checkoutanalytics/v2/analytics", "https://checkoutanalytics-live.adyen.com/checkoutanalytics/v3/analytics-extra",
			"https://checkoutanalytics-unknown.adyen.com/checkoutanalytics/v3/analytics", "https://checkoutshopper-live.adyen.com/checkoutshopper/v2/analytics/log?fixture",
			"https://fixture.chargebee.com/api/internal/track_info_error", "https://api.recurly.com/js/v1/events", "https://analytics.paddle.com/fixture", "https://api.checkout.com/logger/fixture",
		} {
			if !blockTrackerRequest(target, "https://claude.ai/", mode, kindXHR) {
				t.Errorf("%s no longer blocks unrelated tracker %s", mode, target)
			}
		}
		if !blockTrackerRequest("https://c6.paypal.com/fixture", "https://shop.example/", mode, kindImage) {
			t.Errorf("%s no longer blocks PayPal image collection", mode)
		}
	}
	for _, target := range []string{"https://api.mixpanel.com/track", "https://www.googletagmanager.com/gtm.js", "https://o1.ingest.sentry.io/api/1/envelope/", "https://connect.facebook.net/en_US/sdk.js"} {
		if blockTrackerRequest(target, "https://claude.ai/", "standard", kindScript) || !blockTrackerRequest(target, "https://claude.ai/", "strict", kindScript) {
			t.Errorf("payment compatibility changed the privacy tiers for %s", target)
		}
	}
	if !blockTrackerRequest("wss://m.stripe.com/6", "https://claude.ai/", "strict", kindWebsocket) {
		t.Fatal("HTTPS payment exception bypassed WebSocket filtering")
	}
}

func TestPaymentInfrastructureRemainsAllowedWithoutNewExceptions(t *testing.T) {
	for _, request := range []struct {
		url  string
		kind uint16
	}{
		{"https://checkout.link.com/", kindSubdocument},
		{"https://pay.google.com/gp/p/js/pay.js", kindScript},
		{"https://www.paypal.com/sdk/js?client-id=fixture", kindScript},
		{"https://payments.braintree-api.com/graphql", kindXHR},
		{"https://assets.braintreegateway.com/web/3.147.0/html/hosted-fields-frame.html", kindSubdocument},
		{"https://songbird.cardinalcommerce.com/cardinalcruise/v1/songbird.js", kindScript},
		{"https://kg668dbov0.execute-api.us-east-1.amazonaws.com/prod/log", kindXHR},
		{"https://writer.cardinalcommerce.com/prod", kindXHR},
		{"https://checkout-test.adyen.com/v71/sessions", kindXHR},
		{"https://x.klarnacdn.net/kp/lib/v1/api.js", kindScript},
		{"https://cdn.paddle.com/paddle/v2/paddle.js", kindScript},
		{"https://js.chargebee.com/v2/chargebee.js", kindScript},
		{"https://js.recurly.com/v4/recurly.js", kindScript},
	} {
		if paymentServiceExempt(checkedPrivacyURL(request.url)) {
			t.Errorf("ordinary payment infrastructure received an unnecessary exception: %s", request.url)
		}
		for _, mode := range []string{"standard", "strict"} {
			if blockTrackerRequest(request.url, "https://shop.example/checkout", mode, request.kind) {
				t.Errorf("%s blocked payment infrastructure %s", mode, request.url)
			}
		}
	}
}
