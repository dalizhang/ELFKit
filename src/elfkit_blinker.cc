
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>

#include <stdio.h>
#include <stdlib.h>

#include "elfkit_blinker.h"
#include "elfkit_common.h"

namespace elfkit {
    
    fn_dlopen blinker::s_origin_dlopen = NULL;

    blinker::blinker() {

        this->m_soimages.clear();
        this->m_soinfo_list = NULL;
        s_origin_dlopen = dlopen; 
    }
    
    blinker::~blinker() {
        this->m_soimages.clear();
    }
    
    uint32_t blinker::get_sdk_version() {
        char sdk[32] = {0};
        __system_property_get("ro.build.version.sdk", sdk);
        log_dbg("get_sdk_version() -> sdk version: %s\n", sdk);
        return atoi(sdk);
    }
    
    void * blinker::find_library_by_name(const char * soname) {
        if (m_soinfo_list == NULL) {
            char * ld_soname = "libdl.so";
            int sdk_version = blinker::get_sdk_version();
            if (sdk_version >= 26) {
                ld_soname = "ld-android.so";
            }
            m_soinfo_list = dlopen(ld_soname, RTLD_GLOBAL);
            log_info("m_soinfo_list(%p), ld_soname(%s)\n",m_soinfo_list, ld_soname);
            fprintf(stderr, "x0\n");
            dump_hex((uint8_t *)m_soinfo_list, 256);
            fprintf(stderr, "x1\n");
        }

        if (m_soinfo_list) {
            struct soinfo * soinfo = reinterpret_cast<struct soinfo *>(m_soinfo_list);
            while(soinfo) {
                dump_hex((uint8_t *)soinfo, 256);
                log_dbg("%s\n",soinfo->old_name);
                if (strstr((char*)soinfo->old_name, soname)) {
                    return reinterpret_cast<void *>(soinfo);
                }
                soinfo = reinterpret_cast<struct soinfo *>(soinfo->next);
            }
            return NULL;
        }
    }
/*
    soimage * blinker::new_soimage(const char * soname) {
        soimage * image = NULL;
        struct soinfo * s = static_cast<struct soinfo *>(this->find_library_by_name(soname));
        if (s) {
            image = new soimage(s);
        }
        return image;
    }
*/

    soimage * blinker::new_soimage(const char* soname) {
        FILE* fd = fopen("/proc/self/maps", "r");
        if (fd != NULL) {
            char buff[2048+1];
            while(fgets(buff, 2048, fd) != NULL) {
                char *addr = NULL;
                char *flags = NULL;
                char *dev = NULL;
                char *filename = NULL;
                if (phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename)) {
                    if (strstr(filename, soname) != NULL) {
                        if (!check_flags_and_devno(flags, dev)) {
                            continue;
                        }
                        void* base_addr = NULL;
                        void* end_addr = NULL;
                        if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && soimage::check_is_elf_image(base_addr)) {
                            soimage* so = new soimage(reinterpret_cast<ElfW(Addr)>(base_addr), soname);
                            fclose(fd);
                            return so;
                        }
                    } // strstr
                } //phrase_proc_maps_lines
            }// fgets
            fclose(fd);
        }
        return NULL;
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

    int blinker::phrase_proc_maps() {
        int count = 0;
        FILE* fd = fopen("/proc/self/maps", "r");
        if (fd != NULL) {
            char buff[2048+1];
            while(fgets(buff, 2048, fd) != NULL) {
                char *addr = NULL;
                char *flags = NULL;
                char *dev = NULL;
                char *filename = NULL;
                if (phrase_proc_maps_line(buff, &addr, &flags, &dev, &filename)) {
                    if (!check_flags_and_devno(flags, dev)) {
                        continue;
                    }
                    std::string soname = filename;
                    std::map<std::string, soimage>::iterator itor = this->m_soimages.find(soname);
                    if (itor == this->m_soimages.end()) {
                        void* base_addr = NULL;
                        void* end_addr = NULL;
                        if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && 
                                        soimage::check_is_elf_image(base_addr)) {
                            soimage so(reinterpret_cast<ElfW(Addr)>(base_addr), soname.c_str());
                            this->m_soimages.insert(std::pair<std::string, soimage>(soname, so));
                            count += 1;
                        }
                    }
                }
            }
            fclose(fd);
        }
        return count;
    }

};



