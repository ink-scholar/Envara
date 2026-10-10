#include "app-command.h"

/* Linkable standalone entry, outside current installed resource inventory.
 * The future installed native main dispatches app-control commands directly
 * and supplies a compiled private live-session factory for gui-launch-lease.
 * No argv/env/proof can manufacture that factory; this standalone diagnostic
 * default refuses cold staging before stores/claim/fork. */
int main(int argc, char **argv) {
    int status = 1;
    return envara_app_command_dispatch(argc, argv, NULL, &status) ? status : 2;
}
