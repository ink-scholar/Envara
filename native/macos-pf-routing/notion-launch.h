#ifndef ENVARA_NOTION_LAUNCH_H
#define ENVARA_NOTION_LAUNCH_H
#include "app-registry.h"

#define ENVARA_NOTION_DATA_ROOT "/Library/PrivilegedHelperTools/io.envara.pf-app-data"
#define ENVARA_NOTION_SUPPORTED_VERSION "7.34.0"
#define ENVARA_NOTION_SUPPORTED_VERSION_ADDITIONAL "7.37.1"
#define ENVARA_NOTION_ELECTRON_VERSION "43.6.0"
#define ENVARA_NOTION_READY 0

/* Native private context only. The live factory binds this port to a held-open
 * unique front listener, exact realm socket-GID FILTER admission, no lo0 skip,
 * front process birth and this registration/environment/run. Not wire argv,
 * a proxy environment variable, a caller selected path, or a readiness proof. */
struct envara_notion_context {
    char registration_id[37];
    uint16_t front_port;
};
struct envara_notion_plan {
    int ready, protected_ready, resumed;
    char user_data[PATH_MAX], home[PATH_MAX], cache[PATH_MAX], temp[PATH_MAX], extensions[PATH_MAX];
    char shared_data[PATH_MAX];
    /* Root-owned short aliases (gui-launch.h ENVARA_GUI_ALIAS_ROOT) of the
     * UserData and Temp directories above, for socket paths only. */
    char user_data_alias[PATH_MAX], temp_alias[PATH_MAX];
    char posix_locale[64];
    int locale_fallback, argument_count;
    char arguments[13][PATH_MAX];
};
/* Names remain stable for the private native protocol. Capability is derived
 * from the unchanged signed bundle and its contained engine, never app names.
 * VS Code is a narrower Electron capability with explicit extension/shared
 * data flags. It does not provide independent OS Keychain storage. */
enum envara_notion_engine {
    ENVARA_NOTION_ENGINE_NONE = 0,
    ENVARA_NOTION_ENGINE_ELECTRON = 1,
    ENVARA_NOTION_ENGINE_CHROMIUM = 2,
    ENVARA_NOTION_ENGINE_VSCODE = 3
};
int envara_notion_engine(const struct envara_gui_manifest *manifest, enum envara_notion_engine *engine);
/* Read-only signed engine inspection. Never loads application/ASAR code. */
int envara_notion_supported(const struct envara_gui_manifest *manifest);
const char *envara_notion_dns_profile(void);
/* First-app scope: all outbound socket traffic is denied except this exact
 * held IPv4 TCP front. Nonproxy Node/QUIC/UDP requests fail. No generic routing
 * claim follows; external Mach/XPC delegates still require actual acceptance. */
int envara_notion_scoped_profile(uint16_t front_port, const char *socket_root, char *out, size_t capacity);
/* Fixed native activation only. Creates root-owned nonwritable ancestors and
 * exact console-owned 0700 UserData/Home/Cache/Temp/Extensions leaves. The
 * existing UserData login path is unchanged. Never called by plan/status; no
 * caller path, chmod of preexisting data, deletion or original modification. */
int envara_notion_data_prepare(const struct envara_app_registration *app,
    const struct envara_gui_request *request, const struct envara_notion_context *context,
    const struct envara_gui_stage_authority *authority);
/* Only an existing signed root-sealed registered snapshot and pre-created
 * console-owned 0700 UserData under root nonwritable ancestors are accepted.
 * Missing data allocation refuses; plan/status never creates directories. */
int envara_notion_plan(const struct envara_app_registration *app,
    const struct envara_gui_request *request, const struct envara_notion_context *context,
    struct envara_notion_plan *out);
/* Real cold stage via Apple sandbox-exec with fixed DNS broker exclusions and
 * fixed Electron SOCKS/host-resolver/user-data-dir/locale arguments. The fixed
 * native authority must re-attest actual front admission, realm deny, original
 * utun/core and session before fork; this library installs no PF or route.
 * Does not resume. Flags and profile coverage for the selected signed engine,
 * external helpers, keychain/TCC and whole-guard remain acceptance gates. */
int envara_notion_stage(const struct envara_app_registration *app,
    const struct envara_gui_request *request, const struct envara_notion_context *context,
    const struct envara_gui_stage_authority *authority, struct envara_gui_lifecycle *out);
/* Fixed compile-time sub-operation enumeration for the cold-stage internals.
 * The stage, plan, data-preparation and supported-version checks each contain
 * several distinct refusal conditions that all collapse onto the same errno.
 * Without this enumeration a caller cannot tell which internal predicate,
 * syscall or downstream return code failed first, and a repeated errno must not
 * be misread as a second identical refusal.
 *
 * The first sub-operation recorded inside one instrumented invocation wins.
 * Values map to fixed string constants only: never a path, account, PID, node,
 * credential, errno text or arbitrary message. They are explanatory and MUST
 * NOT be consumed as launch, resume, cleanup or resource-ownership authority. */
typedef enum {
    ENVARA_NOTION_SUBOP_NONE = 0,
    /* Read-only supported-version inspection. */
    ENVARA_NOTION_SUBOP_SUPPORTED_ARGUMENT,
    ENVARA_NOTION_SUBOP_SUPPORTED_PLIST,
    ENVARA_NOTION_SUBOP_SUPPORTED_VERSION,
    ENVARA_NOTION_SUBOP_SUPPORTED_SIGNATURE,
    /* Fixed plan construction. */
    ENVARA_NOTION_SUBOP_PLAN_ARGUMENT,
    ENVARA_NOTION_SUBOP_PLAN_REGISTRY,
    ENVARA_NOTION_SUBOP_PLAN_CONTEXT,
    ENVARA_NOTION_SUBOP_PLAN_REQUEST,
    ENVARA_NOTION_SUBOP_PLAN_SEALED,
    ENVARA_NOTION_SUBOP_PLAN_SUPPORTED,
    ENVARA_NOTION_SUBOP_PLAN_DIGEST,
    ENVARA_NOTION_SUBOP_PLAN_CDHASH,
    ENVARA_NOTION_SUBOP_PLAN_REQUIREMENT,
    ENVARA_NOTION_SUBOP_PLAN_DATA,
    ENVARA_NOTION_SUBOP_PLAN_ALLOCATION,
    /* Fixed native data allocation. */
    ENVARA_NOTION_SUBOP_DATA_ARGUMENT,
    ENVARA_NOTION_SUBOP_DATA_ENTRY,
    ENVARA_NOTION_SUBOP_DATA_ANCESTOR,
    ENVARA_NOTION_SUBOP_DATA_LEAF,
    ENVARA_NOTION_SUBOP_DATA_DENY,
    /* Cold stage. */
    ENVARA_NOTION_SUBOP_STAGE_ARGUMENT,
    ENVARA_NOTION_SUBOP_STAGE_AUTHORITY,
    ENVARA_NOTION_SUBOP_STAGE_ENTRY,
    ENVARA_NOTION_SUBOP_STAGE_SESSION,
    ENVARA_NOTION_SUBOP_STAGE_ORIGINAL_RUNNING,
    ENVARA_NOTION_SUBOP_STAGE_ACCOUNT,
    ENVARA_NOTION_SUBOP_STAGE_ENVIRONMENT,
    ENVARA_NOTION_SUBOP_STAGE_DATA,
    ENVARA_NOTION_SUBOP_STAGE_RECHECK,
    ENVARA_NOTION_SUBOP_STAGE_SPAWN,
    ENVARA_NOTION_SUBOP_STAGE_STOPPED
} EnvaraNotionSuboperation;

/* Reset before one instrumented invocation; never inherits a prior result. */
void envara_notion_suboperation_begin(void);
void envara_notion_suboperation_set(EnvaraNotionSuboperation sub);
EnvaraNotionSuboperation envara_notion_suboperation(void);
const char *envara_notion_suboperation_name(EnvaraNotionSuboperation sub);
#endif
