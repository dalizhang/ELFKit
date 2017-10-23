#if !defined(__ELFKIT_BLINKER_H__)
#define __ELFKIT_BLINKER_H__

#include "elfkit_common.h"
#include "elfkit_soimage.h"

#include <string>
#include <map>

namespace elfkit {

    typedef void * (*fn_dlopen)(const char * name, int mode);

    class blinker {
        public:
            blinker();
            ~blinker();
            
        public:
            static uint32_t get_sdk_version();

            void * find_library_by_name(const char * soname);
            soimage * new_soimage(const char * soname);
            int phrase_proc_maps();
        protected:

            bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);
            bool phrase_dev_num(char* devno, int *pmajor, int *pminor);
            bool phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename);
            bool check_flags_and_devno(char* flags, char* dev);

        protected:
        
            static fn_dlopen s_origin_dlopen;        
        
            void * m_soinfo_list;
            std::map<std::string, soimage> m_soimages;
    };

};

#endif

