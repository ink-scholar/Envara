/* Previously verified exact arm64 518 snapshot; never runtime-derived. */
#define ENVARA_PF_UPGRADE_518_SHA256 "518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a"
static const EnvaraPFInstallFile ENVARA_PF_UPGRADE_518_FILES[]={
    {"EnvaraPFHelper","89b32f784003031c3b005898ac2b2e601edeff5ef91e9a4e60dcf5e0d59ff345",0755},
    {"node","ee6fb0e015284d83a91e8ec5213f43a157f8a392b58555301682892ba928c04a",0755},
    {"helper.mjs","6e6ad1aff6f21d0ecdc2908201757f83ba9128f8dcd9338debbef8e41861ba5c",0644},
    {"controller.mjs","eee601ae2e712bd29ba2203ca4dcd2e4bb27504f38e7a00451b9e4b404988244",0644},
    {"policy.mjs","819edf49e18f6812241178b928fa70a492c1b53813b2d09503dd0d387177af6d",0644},
    {"mihomo","94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66",0755},
    {"envara-pf-native","0fe76747a126b31c7021b6d2121c5554862aec779f3767954d46d344f4eac8b8",0755},
    {"fixtures/EnvaraRoutingAcceptanceFixture","85bfa04fdfede1a37553b7b70cef1bed08f3cb19a6e7321ef97f1cef40ae07d6",0755},
    {"node-LICENSE","148eacf7863ef4329224a29398623077200a27194aa075569faf4a0a85566ca5",0644},
    {"mihomo-LICENSE","3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",0644},
    {"mihomo-SOURCE.md","abba5783d51be50d72260f6dea97e3df7b4e6e0cc32a46339cfe357c719e66a0",0644},
    {"mihomo-corresponding-source.tar.gz","6859f30fa7ef47eea24a535e52711d91026adeac905768443aaf1d6f5955dddb",0644},
    {"LICENSE","c5c17ea1c06b26cb4a04e72bef9072dbb6ef52cb36b721a9ee2b98b29e66bc28",0644},
    {"manifest.json","518a75d94bac4f17d9e1ce60e842648ba6ff657a68cc62e95ce13718abda6d5a",0644}
};
static const InstallSnapshot ENVARA_PF_UPGRADE_518_SNAPSHOT={ENVARA_PF_UPGRADE_518_SHA256,ENVARA_PF_UPGRADE_518_FILES,sizeof(ENVARA_PF_UPGRADE_518_FILES)/sizeof(ENVARA_PF_UPGRADE_518_FILES[0])};
