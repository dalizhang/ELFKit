#if !defined(__ELFKIT_BLINKER_H__)
#define __ELFKIT_BLINKER_H__

#include "elfkit_common.h"
#include "elfkit_soimage.h"

#include <string>
#include <map>
#include <unordered_map>

namespace elfkit {

    typedef void * (*fn_soinfo_map_find)(void * map, uintptr_t * handle);
    typedef void * (*fn_dlopen)(const char * name, int flags);
    typedef void * (*fn_dlopen_ext)(const char * soname, int flags, void * extinfo, void * caller_addr);

    class blinker {
        public:
            blinker();
            ~blinker();
            
        public:
            static uint32_t get_sdk_version();
            void load();

            void * find_library_by_name(const char * soname);
            soimage * new_soimage(const char * soname);
            int phrase_proc_maps(std::map<std::string, soimage> & soimages);

        protected:

            bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);
            bool phrase_dev_num(char* devno, int *pmajor, int *pminor);
            bool phrase_proc_maps_line(char* line, char** paddr, char** pflags, char** pdev, char** pfilename);
            bool check_flags_and_devno(char* flags, char* dev);

            bool load_soinfo_list();

        protected:
        
            fn_dlopen               m_origin_dlopen;        
            fn_dlopen_ext           m_origin_dlopen_ext;
            fn_soinfo_map_find      m_origin_soinfo_map_find;

            void            *m_soinfo_list;
            soimage         *m_linker_image;
            void            *m_soinfo_handles_map;     
    };

};

#endif

