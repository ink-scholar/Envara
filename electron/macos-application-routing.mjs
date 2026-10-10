import { NativeApplicationRouting, applicationRoutingError, applicationRoutingReady } from './application-routing.mjs';
import { MacOSLocalRoutingAdapter } from '../native/macos-local-routing/controller.mjs';

/** The original Redirector provides diagnostics; only Envara's AppProxy owns production launches. */
export class MacOSApplicationRouting {
  constructor({ helperPath, peerVerifierPath, bundledAppPath, native, diagnostic } = {}) {
    this.native = native ?? new NativeApplicationRouting({ helperPath, platform: 'darwin' });
    this.diagnostic = diagnostic ?? new MacOSLocalRoutingAdapter({ peerVerifierPath, bundledAppPath });
    this.closed = false;
  }
  assertOpen() {
    if (this.closed) throw applicationRoutingError({ code: 'APPLICATION_ROUTING_CLOSED' });
  }
  async status() {
    this.assertOpen();
    const [primary, diagnostic] = await Promise.allSettled([this.native.status(), this.diagnostic.status()]);
    const state = primary.status === 'fulfilled' ? primary.value : {
      installed: false, authorized: false, ready: false, error: applicationRoutingError(primary.reason).code,
    };
    // Never borrow installation, authorization, checks or sessions from a different provider.
    return { ...state, ...(diagnostic.status === 'fulfilled' && diagnostic.value?.component ? {
      diagnosticComponent: { ...diagnostic.value.component, authorized: diagnostic.value.authorized === true },
    } : {}) };
  }
  async setup(params = {}) {
    this.assertOpen();
    return this.native.setup(params);
  }
  async requireReady() {
    this.assertOpen();
    const state = await this.native.status();
    if (!applicationRoutingReady(state)) throw applicationRoutingError({ code: state?.installed !== true
      ? 'APPLICATION_ROUTING_UNAVAILABLE' : state?.authorized !== true
        ? 'APPLICATION_ROUTING_AUTHORIZATION_REQUIRED' : 'APPLICATION_ROUTING_NOT_READY' });
  }
  async prepareRoute(params) {
    await this.requireReady();
    const application = { path: params?.application?.path, executablePath: params?.application?.executablePath };
    const realm = await this.native.resolveRealm({ application });
    if (typeof realm?.vpnUUID !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(realm.vpnUUID)) {
      throw applicationRoutingError({ code: 'APPLICATION_ROUTING_PROTOCOL_ERROR' });
    }
    // The UUID comes from the helper's installed binding, never a caller-supplied route hint.
    return this.native.prepareRoute({ ...params, vpnUUID: realm.vpnUUID });
  }
  async launch(params) { await this.requireReady(); return this.native.launch(params); }
  stop(params) { this.assertOpen(); return this.native.stop(params); }
  revoke(params) { this.assertOpen(); return this.native.revoke(params); }
  async shutdown() {
    this.closed = true;
    const results = await Promise.allSettled([this.native.shutdown(), this.diagnostic.shutdown()]);
    const failed = results.find(result => result.status === 'rejected');
    if (failed) throw applicationRoutingError(failed.reason);
  }
}
