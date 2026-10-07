package fingerprint

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type geoRoundTripFunc func(*http.Request) (*http.Response, error)

func (f geoRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestQueryUndoIPGeoParsesUndoIMSchema(t *testing.T) {
	requests := make([]string, 0, 1)
	client := &http.Client{Transport: geoRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		if req.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", req.Method)
		}
		if req.URL.String() != "https://undo.im/json" {
			t.Fatalf("request URL = %s, want https://undo.im/json", req.URL.String())
		}
		return geoJSONResponse(req, `{
			"ip": "203.0.113.7",
			"version": "IPv4",
			"cf": {
				"country": "TW",
				"timezone": "Asia/Taipei",
				"city": "Taipei",
				"region": "Taipei City",
				"asn": 3462,
				"asOrganization": "Data Communication Business Group"
			}
		}`), nil
	})}

	country, timezone := queryUndoIPGeo(client, "https://undo.im/json")

	if country != "TW" || timezone != "Asia/Taipei" {
		t.Fatalf("queryUndoIPGeo() = (%q, %q), want (%q, %q)", country, timezone, "TW", "Asia/Taipei")
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %#v, want exactly the primary provider request", requests)
	}
}

func TestQueryIPGeoUsesUndoIMPrimaryResultWithoutLegacyFallback(t *testing.T) {
	oldPrimary, oldLegacy := primaryIPGeoURL, legacyIPGeoURL
	primaryIPGeoURL = "https://undo.im/json"
	legacyIPGeoURL = "http://legacy.test/json/?fields=countryCode,timezone"
	t.Cleanup(func() {
		primaryIPGeoURL, legacyIPGeoURL = oldPrimary, oldLegacy
	})

	requests := make([]string, 0, 1)
	client := &http.Client{Transport: geoRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.URL.String())
		if req.URL.String() == legacyIPGeoURL {
			t.Fatalf("legacy provider was requested after primary undo.im result succeeded")
		}
		if req.URL.String() != primaryIPGeoURL {
			t.Fatalf("request URL = %s, want primaryIPGeoURL %s", req.URL.String(), primaryIPGeoURL)
		}
		return geoJSONResponse(req, `{
			"ip": "198.51.100.9",
			"version": "IPv4",
			"cf": {
				"country": "TW",
				"timezone": "Asia/Taipei",
				"city": "Taipei",
				"region": "Taipei City",
				"asn": 3462,
				"asOrganization": "Data Communication Business Group"
			}
		}`), nil
	})}

	country, timezone := queryIPGeo(client)

	if country != "TW" || timezone != "Asia/Taipei" {
		t.Fatalf("queryIPGeo() = (%q, %q), want (%q, %q)", country, timezone, "TW", "Asia/Taipei")
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %#v, want primary provider only", requests)
	}
}

func TestQueryIPGeoFallsBackToLegacyIPAPIWhenUndoIMUnavailableOrMalformed(t *testing.T) {
	cases := []struct {
		name           string
		primaryFailure func(*http.Request) (*http.Response, error)
	}{
		{
			name: "unavailable",
			primaryFailure: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("undo.im unavailable")
			},
		},
		{
			name: "malformed",
			primaryFailure: func(req *http.Request) (*http.Response, error) {
				return geoJSONResponse(req, `{"ip": "203.0.113.7", "version": "IPv4", "cf": {`), nil
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oldPrimary, oldLegacy := primaryIPGeoURL, legacyIPGeoURL
			primaryIPGeoURL = "https://primary.test/json"
			legacyIPGeoURL = "http://legacy.test/json/?fields=countryCode,timezone"
			t.Cleanup(func() {
				primaryIPGeoURL, legacyIPGeoURL = oldPrimary, oldLegacy
			})

			requests := make([]string, 0, 2)
			client := &http.Client{Transport: geoRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests = append(requests, req.URL.String())
				switch len(requests) {
				case 1:
					if req.URL.String() != primaryIPGeoURL {
						t.Fatalf("first request URL = %s, want primaryIPGeoURL %s", req.URL.String(), primaryIPGeoURL)
					}
					return tc.primaryFailure(req)
				case 2:
					if req.URL.String() != legacyIPGeoURL {
						t.Fatalf("fallback request URL = %s, want legacyIPGeoURL %s", req.URL.String(), legacyIPGeoURL)
					}
					return geoJSONResponse(req, `{"countryCode":"DE","timezone":"Europe/Berlin"}`), nil
				default:
					t.Fatalf("unexpected extra request %d to %s", len(requests), req.URL.String())
					return nil, errors.New("unexpected extra request")
				}
			})}

			country, timezone := queryIPGeo(client)

			if country != "DE" || timezone != "Europe/Berlin" {
				t.Fatalf("queryIPGeo() = (%q, %q), want (%q, %q)", country, timezone, "DE", "Europe/Berlin")
			}
			if len(requests) != 2 {
				t.Fatalf("requests = %#v, want primary then fallback", requests)
			}
		})
	}
}

func TestQueryLegacyIPGeoParsesCountryCodeAndTimezone(t *testing.T) {
	client := &http.Client{Transport: geoRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://ip-api.com/json/?fields=countryCode,timezone" {
			t.Fatalf("request URL = %s, want legacy ip-api endpoint", req.URL.String())
		}
		return geoJSONResponse(req, `{"countryCode":"FR","timezone":"Europe/Paris"}`), nil
	})}

	country, timezone := queryLegacyIPGeo(client, "http://ip-api.com/json/?fields=countryCode,timezone")

	if country != "FR" || timezone != "Europe/Paris" {
		t.Fatalf("queryLegacyIPGeo() = (%q, %q), want (%q, %q)", country, timezone, "FR", "Europe/Paris")
	}
}

func TestConfiguredGeoFallbackUsesEnvironmentTimezoneAndLocale(t *testing.T) {
	t.Setenv("BROWSEFORGE_DEFAULT_TIMEZONE", "Asia/Taipei")
	t.Setenv("BROWSEFORGE_DEFAULT_LOCALE", "zh-TW")
	t.Setenv("TZ", "UTC")

	timezone, locale := configuredGeoFallback()

	if timezone != "Asia/Taipei" || locale != "zh-TW" {
		t.Fatalf("configured fallback = (%q, %q), want (%q, %q)", timezone, locale, "Asia/Taipei", "zh-TW")
	}
}

func TestConfiguredGeoFallbackDerivesLocaleFromTZ(t *testing.T) {
	t.Setenv("TZ", "Asia/Taipei")

	timezone, locale := configuredGeoFallback()

	if timezone != "Asia/Taipei" || locale != "zh-TW" {
		t.Fatalf("configured fallback = (%q, %q), want (%q, %q)", timezone, locale, "Asia/Taipei", "zh-TW")
	}
}

func TestDetectLocalGeoExposesConfiguredFallbackStatus(t *testing.T) {
	oldPrimary, oldLegacy := primaryIPGeoURL, legacyIPGeoURL
	primaryIPGeoURL = "http://127.0.0.1:1/geo"
	legacyIPGeoURL = "http://127.0.0.1:1/legacy"
	t.Cleanup(func() {
		primaryIPGeoURL, legacyIPGeoURL = oldPrimary, oldLegacy
	})
	t.Setenv("BROWSEFORGE_DEFAULT_TIMEZONE", "Asia/Taipei")
	t.Setenv("BROWSEFORGE_DEFAULT_LOCALE", "zh-TW")

	got := DetectLocalGeo()

	if got.Timezone != "Asia/Taipei" || got.Locale != "zh-TW" {
		t.Fatalf("geo fallback values = (%q, %q), want (%q, %q)", got.Timezone, got.Locale, "Asia/Taipei", "zh-TW")
	}
	if got.Source != "configured_fallback" || got.Status != "geo_provider_unavailable" {
		t.Fatalf("geo fallback provenance = (%q, %q), want configured_fallback/geo_provider_unavailable", got.Source, got.Status)
	}
}

func geoJSONResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
