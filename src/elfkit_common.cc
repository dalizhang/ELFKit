#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "elfkit_common.h"

namespace elfkit {
    void dump_hex(uint8_t * pbuf, int size) {
        int i = 0;
        for (int j = 0; j < size; j += 16) {
            i = j;
            fprintf(stderr, "%02X %02X %02X %02X %02X %02X %02X %02X  ", 
                pbuf[i + 0], pbuf[i + 1], pbuf[i + 2], pbuf[i + 3],
                pbuf[i + 4], pbuf[i + 5], pbuf[i + 6], pbuf[i + 7]);
            fprintf(stderr, "%02X %02X %02X %02X %02X %02X %02X %02X\n", 
                pbuf[i + 8], pbuf[i + 9], pbuf[i + 10], pbuf[i + 11],
                pbuf[i + 12], pbuf[i + 13], pbuf[i + 14], pbuf[i + 15]);
        }
        for (int j = i; j < size; j += 1) {
            fprintf(stderr, "%02X ", pbuf[j]);
        }
        fprintf(stderr, "\n");
        return;
    }
    
    bool safe_add(off64_t* out, off64_t a, size_t b) {
        assert(a >= 0);
        if (static_cast<uint64_t>(INT64_MAX - a) < b) {
            return false;
        }
        *out = a + b;
        return true;
    }

    const static struct dyn_name_map_t {
        const char* dyn_name;
        int dyn_tag;
    } s_dyn_name_maps[] = {
        {"DT_NULL",    0},
        {"DT_NEEDED",  1},
        {"DT_PLTRELSZ",2},
        {"DT_PLTGOT",  3},
        {"DT_HASH",    4},
        {"DT_STRTAB",  5},
        {"DT_SYMTAB",  6},
        {"DT_RELA",    7},
        {"DT_RELASZ",  8},
        {"DT_RELAENT", 9},
        {"DT_STRSZ",   10},
        {"DT_SYMENT",  11},
        {"DT_INIT",    12},
        {"DT_FINI",    13},
        {"DT_SONAME",  14},
        {"DT_RPATH",   15},
        {"DT_SYMBOLIC",16},
        {"DT_REL",     17},
        {"DT_RELSZ",   18},
        {"DT_RELENT",  19},
        {"DT_PLTREL",  20},
        {"DT_DEBUG",   21},
        {"DT_TEXTREL", 22},
        {"DT_JMPREL",  23},
        {"DT_LOPROC",   DT_LOPROC},
        {"DT_HIPROC",   DT_HIPROC},
        {"DT_FLAGS_1",  DT_FLAGS_1},
        {"DT_RELCOUNT", DT_RELCOUNT},
        {"DT_GNU_HASH", DT_GNU_HASH},
        {"DT_ANDROID_REL",    DT_ANDROID_REL},
        {"DT_ANDROID_RELSZ",  DT_ANDROID_RELSZ},
        {"DT_ANDROID_RELA",   DT_ANDROID_RELA},
        {"DT_ANDROID_RELASZ", DT_ANDROID_RELASZ},
        {NULL, 0}
    };

    const char * dynamic_tag_to_name(int d_tag) {
        for(int i = 0; s_dyn_name_maps[i].dyn_name != NULL; i++) {
            if (s_dyn_name_maps[i].dyn_tag == d_tag) {
                return s_dyn_name_maps[i].dyn_name;
            }
        }
        return "UNKNOW";
    }
};
