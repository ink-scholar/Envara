package browser

import (
	"encoding/json"
	"fmt"
	"github.com/playwright-community/playwright-go"
)

// Keep the provider adapter identical to electron/privacy-policy.mjs; the
// parity test prevents a URL-resolution or exemption fix reaching only one
// desktop launch path. Only built-in host tiers are used here; EasyPrivacy
// remains active for HTTP(S), and for providers with native routing support.
const constructorWebSocketPolicyScript = `function installConstructorWebSocketPolicy({ mode, domains, serviceRoots, blockLoopback = false }) {
  const NativeWebSocket = globalThis.WebSocket;
  if (typeof NativeWebSocket !== 'function') return;
  const matches = (host, domain) => host === domain || host.endsWith('.' + domain);
  const hostname = (value, relative = false) => {
    try {
      const parsed = relative ? new URL(value, document.baseURI || location.href) : new URL(value);
      return ['http:', 'https:', 'ws:', 'wss:'].includes(parsed.protocol) ? parsed.hostname.toLowerCase().replace(/\.$/, '') : '';
    } catch { return ''; }
  };
  const firstParty = () => {
    try { return hostname(top.location.href); }
    catch {
      // Chromium supplies the ordered ancestor origins for cross-origin
      // frames. Do not borrow the embedded frame's own origin as the top site.
      const ancestors = location.ancestorOrigins;
      return ancestors?.length ? hostname(ancestors[ancestors.length - 1]) : '';
    }
  };
  const WrappedWebSocket = new Proxy(NativeWebSocket, {
    construct(target, args, newTarget) {
      if (args.length) {
        // WebIDL string coercion happens once, preserving native validation
        // of protocols and the rest of the constructor arguments.
        const raw = '' + args[0], host = hostname(raw, true), first = firstParty();
        const domain = domains.find(value => matches(host, value));
        const loopback = host => host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127(?:\.[0-9]{1,3}){3}$/.test(host) || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(host);
        if (blockLoopback && loopback(host) && !loopback(first)) throw new DOMException('Blocked by privacy policy', 'SecurityError');
        if (mode !== 'off' && domain && !(first && (matches(host, first) || matches(first, host) || serviceRoots[domain]?.some(value => matches(first, value))))) {
          throw new DOMException('Blocked by privacy policy', 'SecurityError');
        }
        args = [raw, ...args.slice(1)];
      }
      return Reflect.construct(target, args, newTarget);
    },
  });
  Object.defineProperty(NativeWebSocket.prototype, 'constructor', { ...Object.getOwnPropertyDescriptor(NativeWebSocket.prototype, 'constructor'), value: WrappedWebSocket });
  Object.defineProperty(globalThis, 'WebSocket', { ...Object.getOwnPropertyDescriptor(globalThis, 'WebSocket'), value: WrappedWebSocket });
}`

func installConstructorPrivacyWebSockets(ctx playwright.BrowserContext, state *PrivacyState) error {
	domains := append([]string{}, standardTrackerDomains...)
	if state.Mode == "strict" {
		domains = append(domains, strictTrackerDomains...)
	}
	policy, err := json.Marshal(map[string]any{"mode": state.Mode, "domains": domains, "serviceRoots": trackerServiceRoots, "blockLoopback": true})
	if err != nil {
		return err
	}
	script := fmt.Sprintf("(%s)(%s)", constructorWebSocketPolicyScript, policy)
	if err := ctx.AddInitScript(playwright.Script{Content: playwright.String(script)}); err != nil {
		return err
	}
	for _, page := range ctx.Pages() {
		for _, frame := range page.Frames() {
			if _, err := frame.Evaluate(script); err != nil {
				return err
			}
		}
	}
	return nil
}
