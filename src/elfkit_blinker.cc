
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <libgen.h>

#include <stdio.h>
#include <stdlib.h>

#include "elfkit_blinker.h"
#include "elfkit_common.h"
#include "elfkit_sofile.h"
#include "elfkit_soimage.h"

namespace elfkit {
    

    blinker::blinker() {

        this->m_soinfo_list = NULL;

        this->m_soinfo_handles_map = NULL;

        this->m_origin_dlopen = NULL;
        this->m_origin_dlopen_ext = NULL;
        this->m_origin_soinfo_map_find = NULL;
    }
    
    blinker::~blinker() {
        this->m_soinfo_handles_map = NULL;
        this->m_soinfo_list = NULL;
    }
    
    uint32_t blinker::get_sdk_version() {
        char sdk[32] = {0};
        __system_property_get("ro.build.version.sdk", sdk);
        log_dbg("get_sdk_version() -> sdk version: %s\n", sdk);
        return atoi(sdk);
    }
    
    void * blinker::find_library_by_name(const char * soname) {
       
        if (this->m_soinfo_list) {
            struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
            while(soinfo) {
                // dump_hex((uint8_t *)soinfo, 256);
                //log_dbg("find_library_by_name-> soname(%p), old_name(%s)\n", soname, soinfo->old_name);
                if (strstr((char*)soinfo->old_name, soname)) {
                    return reinterpret_cast<void *>(soinfo);
                }
                soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
            }
        }
        return NULL;
    }

    bool blinker::load_soinfo_list() {

        if (this->m_soinfo_list == NULL) {
            char * ld_soname = "libdl.so";
            int sdk_version = blinker::get_sdk_version();
            if (sdk_version >= 26) {
                ld_soname = "ld-android.so";
            }
            void * libdl_handle = dlopen(ld_soname, RTLD_GLOBAL);
            log_dbg("m_soinfo_list(%p), ld_soname(%s)\n", libdl_handle, ld_soname);
            if ((uintptr_t)libdl_handle & 0x01 == 0) {
                this->m_soinfo_list = libdl_handle;
            } else {
                if (this->m_soinfo_handles_map && this->m_origin_soinfo_map_find) {
                    log_dbg("map:(%p), find(%p)\n", (void*)this->m_soinfo_handles_map, (void*)this->m_origin_soinfo_map_find);
                    void * itor = this->m_origin_soinfo_map_find(this->m_soinfo_handles_map, reinterpret_cast<uintptr_t*>(&libdl_handle));
                    log_dbg("itor:(%p)\n", itor);
                    if (itor != NULL) { // itor != g_soinfo_handles_map.end()
#if defined(__LP64__)
                        this->m_soinfo_list = reinterpret_cast<soinfo *>(*(uint64_t *)((uintptr_t)itor + 0x0c));
#else
                        this->m_soinfo_list = reinterpret_cast<soinfo *>(*(uint32_t *)((uintptr_t)itor + 0x0c));
#endif
                        log_dbg("m_soinfo_list:(%p)\n", (void*)this->m_soinfo_list);
                    }
                }
            }
            if (0 && this->m_soinfo_list) {
                dump_hex((uint8_t *)m_soinfo_list, 256);
            }
        }
        return this->m_soinfo_list != NULL;
        
    }

    soimage * blinker::new_soimage(const char* filename) {

        void * base_addr = NULL;
        void * end_addr = NULL;
        char * soname = basename(filename);
        soimage * so = NULL;
        if (this->m_soinfo_list != NULL) {
            base_addr = find_library_by_name(soname);
            if (soimage::check_is_elf_image(base_addr)) {
                so = new soimage(reinterpret_cast<ElfW(Addr)>(base_addr), soname);
                return so;
            }
        }

        log_dbg("pid(%d) base_addr(%p) from %s[%s]\n", getpid(), base_addr, filename, soname);

        if (!base_addr) {
        /*
            FILE* fd = fopen("/proc/self/maps", "r");
            if (fd != NULL) {
                char buff[2048+1];
                while(fgets(buff, 2048, fd) != NULL) {
                    char *addr = NULL;
                    char *flags = NULL;
                    char *dev = NULL;
                    char *filename = NULL;
                    log_dbg("%s\n", buff);
                    if (!phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename)) {
                        continue;
                    }
                    if (strstr(filename, soname) == NULL) {
                        continue;
                    }
                    if (!check_flags_and_devno(flags, dev)) {
                        continue;
                    }
                    if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && 
                            soimage::check_is_elf_image(base_addr)) {
                        log_dbg("-----> %s\n", addr);
                        break;
                    }
             
                }// fgets
                fclose(fd);
            }
        */
            std::map<std::string, soimage> soimage_list;
            this->phrase_proc_maps(soimage_list);
            auto itor = soimage_list.find(filename);
            if (itor != soimage_list.end()) {
                so = &itor->second;
                log_dbg("base_addr(%p) from soimage\n", (void*)so->get_base_addr());
            }
        }
        return so;
    }

    bool blinker::phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr) {
        char* split = strchr(addr, '-');
        if (split != NULL) {
            if (pbase_addr != NULL) {   
                *pbase_addr = (void *) strtoul(addr, NULL, 16);
            }   
            if (pend_addr != NULL) {   
                *pend_addr = (void *) strtoul(split + 1, NULL, 16);
            }   
            return true;
        }   
        return false;
    }

    bool blinker::phrase_dev_num(char* devno, int *pmajor, int *pminor) {
        *pmajor = 0;
        *pminor = 0;
        
        if (devno != NULL) {
            char* colon_pos = strchr(devno, ':');
            if (colon_pos != NULL) {
                *pmajor = strtoul(devno, NULL, 16);
                *pminor = strtoul(colon_pos + 1, NULL, 16);
                return true;
            }
        }

        return false;
    }

    bool blinker::phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename) {
        const char *sep = "\t \r\n";
        char *buff = NULL;
        char *unused = NULL;
        *paddr = strtok_r(line, sep, &buff);
        *pflags = strtok_r(NULL, sep, &buff);
        unused =strtok_r(NULL, sep, &buff);  // offsets
        *pdev = strtok_r(NULL, sep, &buff);  // dev number.
        unused = strtok_r(NULL, sep, &buff);  // node
        *pfilename = strtok_r(NULL, sep, &buff); //module name
        return (*paddr != NULL && *pfilename != NULL && *pflags != NULL);
    }

    bool blinker::check_flags_and_devno(char* flags, char* dev) {
        if (flags[0] != 'r' || flags[3] == 's') {
            /*
                1. mem section cound NOT be read, without 'r' flag.
                2. read from base addr of /dev/mail module would crash.
                   i dont know how to handle it, just skip it.

                   1f5573000-1f58f7000 rw-s 1f5573000 00:0c 6287 /dev/mali0

            */
            return false;
        }
        int major = 0, minor = 0;
        if (!phrase_dev_num(dev, &major, &minor) || major == 0) {
            /*
                if dev major number equal to 0, mean the module must NOT be
                a shared or executable object loaded from disk.
                e.g:
                lookup symbol from [vdso] would crash.
                7f7b48a000-7f7b48c000 r-xp 00000000 00:00 0  [vdso]
            */
            return false;
        }
        return true;
    }

    int blinker::phrase_proc_maps(std::map<std::string, soimage> & soimages) {
        int count = 0;
        FILE* fd = fopen("/proc/self/maps", "r");
        if (fd != NULL) {
            char buff[2048+1];
            while(fgets(buff, 2048, fd) != NULL) {
                char *addr = NULL;
                char *flags = NULL;
                char *dev = NULL;
                char *filename = NULL;
                log_dbg("%s", buff);
                if (phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename)) {
                    if (!check_flags_and_devno(flags, dev)) {
                        continue;
                    }
                    std::string soname = filename;
                    std::map<std::string, soimage>::iterator itor = soimages.find(soname);
                    if (itor == soimages.end()) {
                        void* base_addr = NULL;
                        void* end_addr = NULL;
                        if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && 
                                        soimage::check_is_elf_image(base_addr)) {
                            soimage so(reinterpret_cast<ElfW(Addr)>(base_addr), soname.c_str());
                            soimages.insert(std::pair<std::string, soimage>(soname, so));
                            count += 1;
                        }
                    }
                }
            }
            fclose(fd);
        }
        return count;
    }

    void blinker::load() {

        soimage * simage = this->new_soimage("/system/bin/linker");
        if (!simage || !simage->load()) {
            log_error("load /system/bin/linker fail\n");
            return;
        }

        uintptr_t base_addr = simage->get_base_addr();
        uintptr_t bias_addr = simage->get_bias_addr();

        delete simage;

        sofile sfile;
        if (!sfile.load("/system/bin/linker")) {
            log_error("read /system/bin/linker fail\n");
            return;
        }

        uintptr_t soinfo_handler_map_offset = static_cast<uintptr_t>(NULL);
        size_t soinfo_handler_map_size = 0;
        if (!sfile.find_variable("__dl__ZL20g_soinfo_handles_map", 
                soinfo_handler_map_offset, 
                soinfo_handler_map_size)) {
            if (!sfile.find_variable("__dl_g_soinfo_handles_map", 
                    soinfo_handler_map_offset, 
                    soinfo_handler_map_size)) {
                log_warn("find g_soinfo_handles_map variable offset fail\n");
            }
        }
        log_dbg("soinfo_handler_map_offset:(%p), soinfo_handler_map_size(%d)\n", (void *)soinfo_handler_map_offset, soinfo_handler_map_size);
        if (soinfo_handler_map_offset) {
            this->m_soinfo_handles_map = reinterpret_cast<void *>(bias_addr + soinfo_handler_map_offset);
        }

        uintptr_t soinfo_map_find_offset = static_cast<uintptr_t>(NULL);
        if (!sfile.find_function("__dl__ZNSt3__112__hash_tableINS_17__hash_value_typeIjP6soinfoEENS_22__unordered_map_hasherIjS4_NS_4hashIjEELb1EEENS_21__unordered_map_equalIjS4_NS_8equal_toIjEELb1EEENS_9allocatorIS4_EEE4findIjEENS_15__hash_iteratorIPNS_11__hash_nodeIS4_PvEEEERKT_",
                soinfo_map_find_offset)) {

            if (!sfile.find_function("__dl__ZNSt3__112__hash_tableINS_17__hash_value_typeIjNS_4pairI9MapStringS3_EEEENS_22__unordered_map_hasherIjS5_NS_4hashIjEELb1EEENS_21__unordered_map_equalIjS5_NS_8equal_toIjEELb1EEENS_9allocatorIS5_EEE4findIjEENS_15__hash_iteratorIPNS_11__hash_nodeIS5_PvEEEERKT_", 
                    soinfo_map_find_offset)) {
                log_warn("find soinfo_map's find function offset fail\n");
            }
        }
        log_dbg("soinfo_map_find_offset:(%p)\n", (void *)soinfo_map_find_offset);
        if (soinfo_map_find_offset) {
            this->m_origin_soinfo_map_find = reinterpret_cast<fn_soinfo_map_find>(bias_addr + soinfo_map_find_offset);
        }

        uintptr_t dlopen_ext_offset = static_cast<uintptr_t>(NULL); 
        if (!sfile.find_function("__dl__ZL10dlopen_extPKciPK17android_dlextinfoPKv", dlopen_ext_offset)) {
            if (!sfile.find_function("__dl__ZL10dlopen_extPKciPK17android_dlextinfoPv", dlopen_ext_offset)) {
                log_warn("find dlopen_ext function offset fail\n");
            }
        }
        log_dbg("dlopen_ext_offset:(%p)\n", (void *)dlopen_ext_offset);
        if (dlopen_ext_offset) {
            this->m_origin_dlopen_ext = reinterpret_cast<fn_dlopen_ext>(bias_addr + dlopen_ext_offset);
        }

        uintptr_t dlopen_offset = static_cast<uintptr_t>(NULL);

        if (sfile.find_function("__dl_dlopen", dlopen_offset)) {
            if (dlopen_offset) {
                this->m_origin_dlopen = reinterpret_cast<fn_dlopen>(bias_addr + dlopen_offset);
            }
        } 
        

        log_dbg("dlopen_offset:(%p) m_origin_dlopen:(%p), dlopen:(%p)\n", 
                    (void *)dlopen_offset,
                    (void *)this->m_origin_dlopen,
                    dlopen);

        // dump_hex((uint8_t*)this->m_origin_soinfo_map_find, 32);

        if (!this->load_soinfo_list()) {
            log_warn("load soinfo list fail.\n");
        }
        return;
    }

};



