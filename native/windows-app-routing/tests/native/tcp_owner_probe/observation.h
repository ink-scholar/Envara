#ifndef ENVARA_TCP_OBSERVATION_H
#define ENVARA_TCP_OBSERVATION_H
#include <stddef.h>
#include <stdint.h>

/* Windows IP Helper tables begin with a DWORD count, followed by ABI padding.
 * The caller supplies offsetof(table, table), never assumes a four-byte offset.
 * This validates bytes only; it grants no packet/endpoint authorization. */
int envara_probe_table_count(const void *, size_t, size_t, size_t, uint32_t *);
/* Microsoft documents ROD data as undefined unless EnableCollection is true. */
int envara_probe_estats_usable(uint32_t result, unsigned enabled);
#endif
