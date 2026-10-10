#ifndef ENVARA_APP_COMMAND_H
#define ENVARA_APP_COMMAND_H
#include "app-supervisor.h"
/* Return 1 when a fixed application command was handled, 0 otherwise.
 * exit_status receives its bounded success/refusal status. Only the installed
 * root main may supply a compiled live provider. NULL permits real registrar
 * and read-only plan commands; preparation/staging explicitly refuse. */
int envara_app_command_dispatch(int argc, char **argv,
    const struct envara_app_supervisor_provider *provider, int *exit_status);
#endif
