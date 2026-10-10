#include "observation.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    uint8_t bytes[40]={0};uint32_t value=2,count=99;
    memcpy(bytes,&value,4);
    assert(envara_probe_table_count(bytes,40,8,16,&count) && count==2);
    assert(!envara_probe_table_count(bytes,39,8,16,&count));
    assert(!envara_probe_table_count(bytes,4,8,16,&count));
    value=UINT32_MAX;memcpy(bytes,&value,4);
    assert(!envara_probe_table_count(bytes,sizeof(bytes),8,16,&count));
    value=0;memcpy(bytes,&value,4);
    assert(envara_probe_table_count(bytes,4,8,16,&count) && count==0);
    assert(!envara_probe_table_count(bytes,3,8,16,&count));
    assert(!envara_probe_table_count(bytes,sizeof(bytes),8,0,&count));
    assert(!envara_probe_table_count(NULL,sizeof(bytes),8,16,&count));
    assert(!envara_probe_estats_usable(0,0));
    assert(!envara_probe_estats_usable(5,1));
    assert(!envara_probe_estats_usable(0,2));
    assert(envara_probe_estats_usable(0,1));
    puts("TCP observation buffer/undefined-data tests passed");return 0;
}
