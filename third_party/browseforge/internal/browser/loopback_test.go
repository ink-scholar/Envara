package browser

import "testing"

func TestLoopbackHost(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://127.0.0.1:53123/callback?code=x": true, "http://localhost:8080/": true, "http://[::1]:9/": true,
		"http://127.12.0.1/": true, "http://app.localhost/": true, "https://example.com/": false, "http://10.0.0.1/": false,
		"http://127.0.0.1.example.com/": false, "not a url": false,
	} {
		if got := loopbackHost(raw); got != want {
			t.Fatalf("loopbackHost(%q) = %v, want %v", raw, got, want)
		}
	}
	if loopbackProxyBypass != "127.0.0.1,localhost,[::1]" {
		t.Fatalf("loopback bypass changed: %q", loopbackProxyBypass)
	}
}
