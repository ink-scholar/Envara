#include "app-command.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int envara_app_command_dispatch(int argc, char **argv,
    const struct envara_app_supervisor_provider *provider, int *exit_status) {
    if (!exit_status || argc < 2 || !argv || !argv[1]) return 0;
    const char *commands[] = {"app-register", "app-plan", "app-retire", "app-ticket-prepare", "app-ticket-inspect"};
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) if (!strcmp(argv[1], commands[i])) {
        struct envara_app_control_context context = {0};
        context.authority = provider ? &provider->ticket : NULL;
        *exit_status = envara_app_control_dispatch(&context, argc, (const char *const *)argv, STDOUT_FILENO) ? 1 : 0;
        return 1;
    }
    if (strcmp(argv[1], "gui-launch-lease")) return 0;
    struct envara_app_supervisor_context context = {.provider = provider}; struct envara_app_supervisor_report report;
    int result = argc == 3 ? envara_app_supervisor_run(&context, argv[2], STDOUT_FILENO, &report) : -1;
    if (result) {
        int error = argc == 3 ? errno : EINVAL;
        printf("{\"schema\":\"%s\",\"event\":\"refused\",\"error\":%d,\"reason\":\"LIVE_FIXED_NATIVE_SUPERVISOR_AUTHORITY_REQUIRED\",\"ready\":false,\"protected\":false}\n",
            ENVARA_APP_KEEPER_PROTOCOL, error);
    }
    *exit_status = result ? 1 : 0; return 1;
}
