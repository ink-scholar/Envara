/* Fixed 05d6/run877 READ-ONLY inventory. No cleanup/token/DELETE entry. */
#define CANARY_RUN @"877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21"
#define CANARY_ANCHOR @"io.envara.pf.run.877ab9cc-ed91-4f2d-a8cd-86cedc2f3e21"
#define CANARY_MANIFEST_SHA "05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061"
#define CANARY_NATIVE_SHA "724bf55d769a77aa6ed48addd8cbea7ab03fd1a2ee226f7ccf50862fc4837ff1"
typedef struct {const char *name,*sha;mode_t mode;} CanaryFile;
static const CanaryFile files[]={
{"node","ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a",0755},
{"node-LICENSE","148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5",0644},
{"mihomo","94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66",0755},
{"mihomo-LICENSE","3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",0644},
{"mihomo-SOURCE.md","abba5783d51be50d72260f6dea97e3df7b4e6e0cc32a46339cfe357c719e66a0",0644},
{"mihomo-corresponding-source.tar.gz","6859f30fa7ef47eea24a535e52711d91026adeac905768443aaf1d6f5955dddb",0644},
{"envara-pf-native","724bf55d769a77aa6ed48addd8cbea7ab03fd1a2ee226f7ccf50862fc4837ff1",0755},
{"helper.mjs","6e6ad1aff6f21d0ecdc2908201757f83ba9128f8dcd9338debbef8e41861ba5c",0644},
{"controller.mjs","97c1f5856dc5ea8a7743e85f7a8c49c61ec8e4dd2c10ec497839556af146270f",0644},
{"helper-production-native.mjs","f5ea96b53b827c912e241664ee890aa2dd431c803d5f0e7658c79e18f09cfd9f",0644},
{"notion-front-service.mjs","854b34bd6ac1f045cc85cfd6109cb471b9b9a632915a6a7d87cc0b817593671c",0644},
{"notion-socks-front.mjs","dfe30e6bba7b28e0f7ed67bf76178affff6c2b0ab86f610aafb64da03cf2d847",0644},
{"notion-socks-reader.mjs","4157eaa561efd7e7fe39e4c607a01d7bbfce5ec2bdb1aa98a1a93f044e3efeae",0644},
{"policy.mjs","02deb8c99596939034e3d1338c42daa5b1cbda66f8ba4d412bb5c7147ea89cde",0644},
{"stateless-verifier.mjs","13f09ec1c42d8dfe5541b692fb10a3667d10469450c3717ec18584a2cb26b9a6",0644},
{"EnvaraPFHelper","89b32f784003031c3b005898ac2b2e601edeff5ef91e9a4e60dcf5e0d59ff345",0755},
{"LICENSE","c5c17ea1c06b26cb4a04e72bef9072dbb6ef52cb36b721a9ee2b98b29e66bc28",0644},
{"fixtures/EnvaraRoutingAcceptanceFixture","4944df4dbd5032b756149e1ffb4156e5d25874e3c10e9e5d33ce87b3deddc763",0755},
{"manifest.json","05d6eb6ab3d63870d37825b47e2847789a6b5b8c3cf93c434636e0b8aad4f061",0644},
};
