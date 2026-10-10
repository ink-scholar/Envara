#include "app-control.h"
#include <unistd.h>
/* Compile separately for source review. No fixture path/authority CLI exists.
 * Future fixed envara-pf-native main must dispatch using its private native
 * authority and persistent GUI supervisor. This entry never stages a child. */
int main(int argc, char **argv) { return envara_app_control_dispatch(NULL, argc, (const char *const *)argv, STDOUT_FILENO) ? 1 : 0; }
