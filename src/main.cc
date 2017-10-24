#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <dlfcn.h>
#include "elfkit_common.h"
#include "elfkit_blinker.h"
#include "elfkit_soimage.h"
#include "elfkit_sofile.h"
using namespace elfkit;

typedef uint32_t (*fn_get_sdk_version)(void);

void test() {
    void * h = dlopen("/system/lib/libexpat.so", RTLD_GLOBAL);
    fprintf(stderr, "h:%p\n",h);
    if (h) {
        fn_get_sdk_version fn = (fn_get_sdk_version)dlsym(h, "android_get_application_target_sdk_version");
        fprintf(stderr, "v: %p\n", fn);
        fprintf(stderr, "sdk version: %x\n", fn());
    }
}

int main(const int argc, const char * argv[]) {
    blinker linker;
    fprintf(stderr, "ELFKit demo!\n");

    linker.load();

    fprintf(stderr, "- - - - - - - - - - - - - - -\n");
    soimage * s = linker.new_soimage("/system/lib/libdl.so");
    if (!s->load()) {
        fprintf(stderr, "soimage(libdl.so) load fail\n");
        return 0;
    }
    sofile f;
    if (f.load("/system/lib/libdl.so")) {
        uintptr_t dlopen_offset = static_cast<uintptr_t>(NULL);
        f.find_function("dlopen", dlopen_offset);
        void * dlopen_func = reinterpret_cast<void *>(s->get_bias_addr() + dlopen_offset);
        fprintf(stderr ,"dlopen_offset(%p), dlopen_func(%p), dlopen(%p)\n", 
                (void *)dlopen_offset,
                dlopen_func,
                dlopen);
    }
    char c = fgetc(stdin);

    return 0;
}