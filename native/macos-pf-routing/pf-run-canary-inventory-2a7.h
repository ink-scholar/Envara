/* Independent fixed-2a7 empty-v2-hook candidate. Never regenerate this UUID
 * when rebuilding: native ledger burns it permanently before INSERT. */
#ifndef ENVARA_PF_RUN_CANARY_2A7_INVENTORY_H
#define ENVARA_PF_RUN_CANARY_2A7_INVENTORY_H
#define CANARY_RUN @"06d57c81-373e-49ab-9b07-27563497293a"
#define CANARY_ANCHOR @"io.envara.pf.run.06d57c81-373e-49ab-9b07-27563497293a"
#define CANARY_MANIFEST_SHA "2a7f4ad635041c434b511034e9535b688cee8eeaebce97617586ad142db5f02d"
#define CANARY_NATIVE_SHA "8259641a73e96a28a8d1ca373b2d51c066bb74fafd91450e3f59279a477844b8"
typedef struct { const char *name, *sha; mode_t mode; } CanaryFile;
static const CanaryFile files[] = {
 {"manifest.json", CANARY_MANIFEST_SHA, 0644},
 {"node", "ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a", 0755},
 {"node-LICENSE", "148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5", 0644},
 {"mihomo", "94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66", 0755},
 {"mihomo-LICENSE", "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986", 0644},
 {"mihomo-SOURCE.md", "abba5783d51be50d72260f6dea97e3df7b4e6e0cc32a46339cfe357c719e66a0", 0644},
 {"mihomo-corresponding-source.tar.gz", "6859f30fa7ef47eea24a535e52711d91026adeac905768443aaf1d6f5955dddb", 0644},
 {"envara-pf-native", "8259641a73e96a28a8d1ca373b2d51c066bb74fafd91450e3f59279a477844b8", 0755},
 {"helper.mjs", "6e6ad1aff6f21d0ecdc2908201757f83ba9128f8dcd9338debbef8e41861ba5c", 0644},
 {"controller.mjs", "2d7d12125886bb4ae7c5b4f7210cd61457169858eebc82278664ab9db7f79dbd", 0644},
 {"policy.mjs", "02deb8c99596939034e3d1338c42daa5b1cbda66f8ba4d412bb5c7147ea89cde", 0644},
 {"stateless-verifier.mjs", "13f09ec1c42d8dfe5541b692fb10a3667d10469450c3717ec18584a2cb26b9a6", 0644},
 {"EnvaraPFHelper", "89b32f784003031c3b005898ac2b2e601edeff5ef91e9a4e60dcf5e0d59ff345", 0755},
 {"LICENSE", "c5c17ea1c06b26cb4a04e72bef9072dbb6ef52cb36b721a9ee2b98b29e66bc28", 0644},
 {"fixtures/EnvaraRoutingAcceptanceFixture", "85bfa04fdfede1a37553b7b70cef1bed08f3cb19a6e7321ef97f1cef40ae07d6", 0755},
};
#endif
