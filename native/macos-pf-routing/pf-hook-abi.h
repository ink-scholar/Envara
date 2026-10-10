#ifndef ENVARA_PF_HOOK_ABI_H
#define ENVARA_PF_HOOK_ABI_H
#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>
/* Fixed generated layout: Mullvad pfctl-rs 0.7.0,
 * 273e96bec0f5b983f16cfd43b6512f4c97a3f848, src/ffi/pfvar.rs
 * SHA256 e09ade2fe4be76579bd8185eeccd561deb9f89f84db69dc5ae50a386425b78d6.
 * Current Darwin 27 source is unpublished. Only the separately approved
 * empty-entry INSERT/GET/DELETE was observed; complete layout stays unverified.
 * Frozen primary observation: root-canary-native-20261008.json.
 */
typedef struct __attribute__((aligned(8))) {
    uint8_t src[64], dst[64], skip[64];
    char label[64], ifname[16];
    uint8_t opaque272[376];
    uint64_t evaluations, packets[2], bytes[2], ticket;
    char owner[64];
    uint32_t priority;
    uint8_t opaque764[184];
    uint32_t nr;
    uint8_t opaque952[24];
    uint32_t uid[2]; uint8_t uid_op, uid_pad[3];
    uint32_t gid[2]; uint8_t gid_op, gid_pad[3];
    uint32_t rule_flag;
    uint8_t action, direction, log, logif, quick, ifnot, match_tag_not,
        natpass, keep_state, af, proto, type, code, flags, flagset, min_ttl,
        allow_opts, rt, return_ttl, tos, anchor_relative, anchor_wildcard,
        flush, proto_variant, extfilter, extmap, pad1030[2];
    uint32_t dnpipe, dntype;
} EnvaraPFHookRule;
typedef struct {
    uint32_t action, ticket, pool_ticket, nr;
    char anchor[1024], anchor_call[1024];
    EnvaraPFHookRule rule;
} EnvaraPFHookRequest;
#define ASSERT_OFFSET(type, field, value) _Static_assert(offsetof(type, field) == value, #field " layout mismatch")
_Static_assert(sizeof(EnvaraPFHookRule) == 1040, "rule size mismatch");
_Static_assert(_Alignof(EnvaraPFHookRule) == 8, "rule alignment mismatch");
_Static_assert(sizeof(EnvaraPFHookRequest) == 3104, "request size mismatch");
ASSERT_OFFSET(EnvaraPFHookRequest, action, 0); ASSERT_OFFSET(EnvaraPFHookRequest, ticket, 4);
ASSERT_OFFSET(EnvaraPFHookRequest, nr, 12); ASSERT_OFFSET(EnvaraPFHookRequest, anchor, 16);
ASSERT_OFFSET(EnvaraPFHookRequest, anchor_call, 1040); ASSERT_OFFSET(EnvaraPFHookRequest, rule, 2064);
ASSERT_OFFSET(EnvaraPFHookRule, label, 192); ASSERT_OFFSET(EnvaraPFHookRule, ifname, 256);
ASSERT_OFFSET(EnvaraPFHookRule, ticket, 688); ASSERT_OFFSET(EnvaraPFHookRule, owner, 696);
ASSERT_OFFSET(EnvaraPFHookRule, priority, 760); ASSERT_OFFSET(EnvaraPFHookRule, nr, 948);
ASSERT_OFFSET(EnvaraPFHookRule, uid, 976); ASSERT_OFFSET(EnvaraPFHookRule, gid, 988);
ASSERT_OFFSET(EnvaraPFHookRule, gid_op, 996); ASSERT_OFFSET(EnvaraPFHookRule, rule_flag, 1000);
ASSERT_OFFSET(EnvaraPFHookRule, action, 1004); ASSERT_OFFSET(EnvaraPFHookRule, direction, 1005);
ASSERT_OFFSET(EnvaraPFHookRule, quick, 1008); ASSERT_OFFSET(EnvaraPFHookRule, keep_state, 1012);
ASSERT_OFFSET(EnvaraPFHookRule, af, 1013); ASSERT_OFFSET(EnvaraPFHookRule, proto, 1014);
#define ENVARA_PF_HOOK_GET_RULES _IOWR('D', 6, EnvaraPFHookRequest)
#define ENVARA_PF_HOOK_GET_RULE _IOWR('D', 7, EnvaraPFHookRequest)
_Static_assert(ENVARA_PF_HOOK_GET_RULES == 0xcc204406UL, "GETRULES encoding mismatch");
_Static_assert(ENVARA_PF_HOOK_GET_RULE == 0xcc204407UL, "GETRULE encoding mismatch");

#define ENVARA_PF_HOOK_INSERT _IOWR('D', 27, EnvaraPFHookRequest)
#define ENVARA_PF_HOOK_DELETE _IOWR('D', 28, EnvaraPFHookRequest)
_Static_assert(ENVARA_PF_HOOK_INSERT == 0xcc20441bUL, "INSERT encoding mismatch");
_Static_assert(ENVARA_PF_HOOK_DELETE == 0xcc20441cUL, "DELETE encoding mismatch");
#undef ASSERT_OFFSET
#endif
