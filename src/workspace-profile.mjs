

const profileFields = ["name", "group", "notes", "engine", "platform", "seed", "locale", "timezone", "width", "height", "startUrl", "proxyId", "privacy", "deviceProfileId"];

export const profileConfig = profile => ({
  ...Object.fromEntries(profileFields.filter(key => profile[key] != null || key === "proxyId").map(key => [key, profile[key]])),
  proxyId: Object.hasOwn(profile, "profileProxyId") ? profile.profileProxyId : profile.proxyId
});

const runtimeOrder = new Map(["cloakbrowser", "camoufox", "browseforge-chromium"].map((id, index) => [id, index]));

export const runtimeCatalog = snapshot => [...(snapshot.engines?.length ? snapshot.engines : [{
  id: "cloakbrowser",
  displayName: "CloakBrowser",
  family: "chromium",
  supported: true,
  capabilities: {},
  ...snapshot.engine
}])].sort((a, b) => (runtimeOrder.get(a.id) ?? 99) - (runtimeOrder.get(b.id) ?? 99));

export const allows = (runtime, key) => {
  const capability = {
    seed: "supports_seed_fingerprint",
    proxy: "supports_native_proxy"
  }[key];
  return capability && Object.hasOwn(runtime?.capabilities || {}, capability) ? runtime.capabilities[capability] !== false : runtime?.capabilities?.[key] !== false;
};

export const platforms = {
  macos: "macOS",
  windows: "Windows",
  linux: "Linux"
};
