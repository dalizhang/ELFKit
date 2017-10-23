#if !defined(__ELFKIT_SOIMAGE_H__)
#define __ELFKIT_SOIMAGE_H__

#include <string>
#include "elfkit_common.h"
#include "elfkit_soinfo.h"

namespace elfkit {

    class soimage {

        public:
            soimage(struct soinfo * soinfo);
            soimage(ElfW(Addr) base_addr, const char * soname);
            ~soimage();

            bool load();
            bool hook(const char *symbol, void *replace_func, void **old_func);

            static bool check_is_elf_image(void* base_addr);

            inline const char * get_soname() {return m_soname.c_str();}
            inline ElfW(Addr) get_base_addr() {return m_base_addr;}
            inline ElfW(Addr) get_bias_addr() {return m_bias_addr;}
            inline size_t get_load_size() {return m_phdr_load_size;}

            void dump_elf_header(void);
            void dump_sections(void);
            void dump_segments(void);
            void dump_dynamics(void);
            void dump_symbols(void);
            void dump_rel_info(void);
            void dump_rela_info(void);

        protected:

            ElfW(Addr) get_exec_load_bias_addr(const ElfW(Ehdr)* ehdr);
            size_t get_phdr_table_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count);

            uint32_t elf_hash(const char * name);
            uint32_t gnu_hash(const char * name);

            ElfW(Phdr)* find_segment_by_type(const ElfW(Word) type);
            ElfW(Shdr)* find_section_by_name(const char * sname);

            bool gnu_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx);
            bool elf_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx);
            bool find_symbol_by_name(const char *symbol, ElfW(Sym) **sym, int *symidx);

            template<class T>
            void get_segment_info(const ElfW(Word) type, ElfW(Phdr) **ppPhdr, ElfW(Word) *pSize, T *data);
            template<class T>
            void get_section_info(const char *name, ElfW(Shdr) **ppShdr, ElfW(Word) *pSize, T *data);

            int  clear_cache(void *addr, size_t len);
            int  get_mem_access(ElfW(Addr) addr, uint32_t* pprot);
            int  set_mem_access(ElfW(Addr)
            addr, int prots);
            bool replace_function(void *addr, void *replace_func, void **old_func);

            inline bool get_is_gnu_hash() { return this->m_is_gnu_hash; }
            inline void set_is_gnu_has(bool flag) { this->m_is_gnu_hash = flag; }
            inline bool get_is_use_rela() { return this->m_is_use_rela; }
            inline void set_is_use_rela(bool flag) { this->m_is_use_rela = flag; }

        protected:

            ElfW(Addr)      m_base_addr;
            ElfW(Addr)      m_bias_addr;
            std::string     m_soname;
            bool            m_is_loaded;
            size_t          m_phdr_load_size;
            
        protected:

            ElfW(Ehdr)  *m_ehdr;
            ElfW(Phdr)  *m_phdr;
            ElfW(Shdr)  *m_shdr;

            ElfW(Dyn)   *m_dyn_ptr;
            ElfW(Word)  m_dyn_size;

            ElfW(Sym)    *m_sym_ptr;
            ElfW(Word)   m_sym_size;

            ElfW(Addr)   m_relplt_addr;
            ElfW(Addr)   m_reldyn_addr;

            ElfW(Word)  m_relplt_bytes;
            ElfW(Word)  m_reldyn_bytes;


        protected:
            //for elf hash
            uint32_t    m_nbucket;
            uint32_t    m_nchain;
            uint32_t    *m_bucket;
            uint32_t    *m_chain;

            //for gnu hash
            uint32_t   m_gnu_nbucket;
            uint32_t   m_gnu_symndx;
            uint32_t   m_gnu_maskwords;
            uint32_t   m_gnu_shift2;
            uint32_t   *m_gnu_bucket;
            uint32_t   *m_gnu_chain;
            ElfW(Addr) *m_gnu_bloom_filter;

            bool m_is_gnu_hash;
            bool m_is_use_rela;

        protected:

            const char  *m_shstr_ptr;
            const char  *m_symstr_ptr;

    };


};

#endif

