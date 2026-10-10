#include "observation.h"
#include <string.h>

int envara_probe_table_count(const void *data, size_t bytes, size_t offset, size_t row, uint32_t *count) {
    uint32_t value;
    if (!data || !count || bytes < sizeof(value) || offset < sizeof(value) || !row) return 0;
    memcpy(&value, data, sizeof(value));
    if (value && (offset > bytes || value > (bytes-offset)/row)) return 0;
    *count=value;
    return 1;
}
int envara_probe_estats_usable(uint32_t result, unsigned enabled) {
    return result==0 && enabled==1;
}
