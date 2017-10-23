
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <assert.h>

#include "elfkit_common.h"
#include "elfkit_soimage.h"

namespace elfkit {

    soimage::soimage(struct soinfo * soinfo) {
        char * soname = soinfo->old_name;
        ElfW(Addr) base_addr = static_cast<ElfW(Addr)>(soinfo->base);
        soimage(base_addr, soname);
    }    

    soimage::soimage(ElfW(Addr) base_addr, const char * soname) {

        this->m_base_addr   = base_addr;
        this->m_soname      = soname;
        this->m_bias_addr   = 0;
        this->m_is_loaded   = false;

        this->m_ehdr          = NULL;
        this->m_phdr          = NULL;
        this->m_shdr          = NULL;

        this->m_dyn_ptr       = NULL;
        this->m_dyn_size      = 0;

        this->m_sym_ptr       = NULL;
        this->m_sym_size      = 0;

        this->m_relplt_addr     = 0;
        this->m_relplt_bytes    = 0;
        this->m_reldyn_addr     = 0;
        this->m_reldyn_bytes    = 0;


        this->m_symstr_ptr    = NULL;
        this->m_shstr_ptr     = NULL;

        this->set_is_gnu_has(false);
        this->set_is_use_rela(false);
    }

    soimage::~soimage() {

    }
    
    size_t soimage::get_phdr_table_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count) {
        ElfW(Addr) min_vaddr = UINTPTR_MAX;
        ElfW(Addr) max_vaddr = 0;

        bool found_pt_load = false;
        for (size_t i = 0; i < phdr_count; ++i) {
            const ElfW(Phdr)* phdr = &phdr_table[i];

            if (phdr->p_type != PT_LOAD) {
              continue;
            }
            fprintf(stderr, "PT_LOAD, 0x%08X, 0x%08X\n", phdr->p_vaddr, phdr->p_memsz);
            found_pt_load = true;

            if (phdr->p_vaddr < min_vaddr) {
              min_vaddr = phdr->p_vaddr;
            }

            if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
              max_vaddr = phdr->p_vaddr + phdr->p_memsz;
            }
        }
        if (!found_pt_load) {
            min_vaddr = 0;
        }

        min_vaddr = PAGE_START(min_vaddr);
        max_vaddr = PAGE_END(max_vaddr);
        return max_vaddr - min_vaddr;
    }

    bool soimage::check_is_elf_image(void* base_addr) {
        ElfW(Ehdr) *ehdr = reinterpret_cast<ElfW(Ehdr) *>(base_addr);
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
            return false;
        }
        int elf_class = ehdr->e_ident[EI_CLASS];
#if defined(__LP64__)
        if (elf_class != ELFCLASS64) {
            return false;
        }
#else
        if (elf_class != ELFCLASS32) {
            return false;
        }
#endif
        if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
            return false;
        }
        if (ehdr->e_version != EV_CURRENT) {
            return false;
        }
        if (ehdr->e_machine != GetTargetElfMachine()) {
            return false;
        }
        return true;
    }
    bool soimage::load() {
        if (this->m_is_loaded) {
            return true;
        }
        this->m_ehdr = reinterpret_cast<ElfW(Ehdr) *>(this->get_base_addr());
        this->m_shdr = reinterpret_cast<ElfW(Shdr) *>(this->get_base_addr() + this->m_ehdr->e_shoff);
        this->m_phdr = reinterpret_cast<ElfW(Phdr) *>(this->get_base_addr() + this->m_ehdr->e_phoff);
        if (!this->m_bias_addr) {
            this->m_bias_addr = this->get_exec_load_bias_addr(this->m_ehdr);
        }
        
        fprintf(stderr, "%p,%p,%p,%p\n", 
                        (void*)this->get_base_addr(), 
                        (void*)this->get_bias_addr(),
                        (void*)this->m_ehdr->e_phoff,
                        (void*)this->m_ehdr->e_shoff);
        
        if (this->m_ehdr->e_type == ET_EXEC || this->m_ehdr->e_type == ET_DYN) {
            log_info("Executable File or Shared Object, loading ..\n");
        } else {
            log_error("ELF (%08x) object, DONOT load..\n", this->m_ehdr->e_type);
            return false;
        }

        this->m_phdr_load_size = this->get_phdr_table_load_size(this->m_phdr, this->m_ehdr->e_phnum);
        this->m_shstr_ptr = NULL;

        ElfW(Phdr) *dynamic = NULL;
        ElfW(Word) size = 0;
        this->get_segment_info(PT_DYNAMIC, &dynamic, &size, &this->m_dyn_ptr);
        if(!dynamic) {
            log_error("Could't find PT_DYNAMIC segment\n");
            return false;
        }
        ElfW(Dyn) *dyn = this->m_dyn_ptr;
        this->set_is_gnu_has(false);
        this->m_dyn_size = size / sizeof(Elf32_Dyn);
        for(int i = 0; i < (int)this->m_dyn_size; i += 1, dyn += 1) {
            switch(dyn->d_tag) {
        //    case SHT_DYNSYM:

            case DT_SYMTAB:
                this->m_sym_ptr = reinterpret_cast<ElfW(Sym) *>(this->get_bias_addr() + dyn->d_un.d_ptr);
                break;
            case DT_STRTAB:
                this->m_symstr_ptr = reinterpret_cast<const char *>(this->get_bias_addr() + dyn->d_un.d_ptr);
                break;
            case DT_PLTREL:
                  if (dyn->d_un.d_val == DT_RELA) {
                      this->set_is_use_rela(true);
                  }
                  break;
            case DT_REL:
            case DT_ANDROID_REL:
                this->m_reldyn_addr = reinterpret_cast<ElfW(Addr)>(this->get_bias_addr() + dyn->d_un.d_ptr);
                break;
            case DT_RELSZ:
            case DT_ANDROID_RELSZ:
                this->m_reldyn_bytes = dyn->d_un.d_val;
                break;
            case DT_JMPREL:
                this->m_relplt_addr = reinterpret_cast<ElfW(Addr)>(this->get_bias_addr() + dyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                this->m_relplt_bytes = dyn->d_un.d_val;
                break;
            case DT_HASH: {
                    uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->get_bias_addr() + dyn->d_un.d_ptr);
                    this->m_nbucket = rawdata[0];
                    this->m_nchain  = rawdata[1];
                    this->m_bucket  = rawdata + 2;
                    this->m_chain   = this->m_bucket + this->m_nbucket;
                    this->m_sym_size   = this->m_nchain;
                    log_dbg("parse DT_HASH section : nbucket(%d), nchain(%d), bucket(%p), chain(%p)\n", this->m_nbucket, this->m_nchain, this->m_bucket, this->m_chain);
                    break;
                }
            case DT_GNU_HASH: {
                    uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->get_bias_addr() + dyn->d_un.d_ptr);
                    this->m_gnu_nbucket      = rawdata[0];
                    this->m_gnu_symndx       = rawdata[1];
                    this->m_gnu_maskwords    = rawdata[2];
                    this->m_gnu_shift2       = rawdata[3];
                    this->m_gnu_bloom_filter = reinterpret_cast<ElfW(Addr)*>(this->get_bias_addr() + dyn->d_un.d_ptr + 16);
                    this->m_gnu_bucket       = reinterpret_cast<uint32_t*>(this->m_gnu_bloom_filter + this->m_gnu_maskwords);
                    this->m_gnu_chain        = this->m_gnu_bucket + this->m_gnu_nbucket - this->m_gnu_symndx;


                    if (!powerof2(this->m_gnu_maskwords)) {
                        log_error("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                                this->m_gnu_maskwords, get_soname());
                        return false;
                    }
                    this->m_gnu_maskwords -= 1;
                    this->set_is_gnu_has(true);

                    log_dbg("bbucket(%d), symndx(%d), maskworks(%d), shift2(%d)\n",
                            this->m_gnu_nbucket,   this->m_gnu_symndx,
                            this->m_gnu_maskwords, this->m_gnu_shift2);
                    break;
                }
            }
        }
        this->m_is_loaded = true;
        return this->m_is_loaded;
    }

    bool soimage::hook(const char *symbol, void *replace_func, void **old_func) {
        ElfW(Sym) *sym = NULL;
        int symidx = 0;

        assert(old_func);
        assert(replace_func);
        assert(symbol);

        if (!this->load()) {
            return false;
        }

        this->find_symbol_by_name(symbol, &sym, &symidx);
        if(!sym) {
            log_error("Could not find symbol %s\n", symbol);
            return false;
        } else {
            log_dbg("Found sym %p, symidx %d.\n", sym, symidx);
        }

        int relplt_counts = this->get_is_use_rela() ? this->m_relplt_bytes / sizeof(ElfW(Rela)) : this->m_relplt_bytes / sizeof(ElfW(Rel));
        for (uint32_t i = 0; i < relplt_counts; i++) {
            unsigned long r_info = 0;   // for Elf32 it's Elf32_Word, but Elf64 it's Elf64_Xword.
            ElfW(Addr) r_offset = 0;
            if (this->get_is_use_rela()) {
                ElfW(Rela) *rela = reinterpret_cast<ElfW(Rela) *>(this->m_relplt_addr + sizeof(ElfW(Rela)) * i);
                r_info = (unsigned long)rela->r_info;
                r_offset = rela->r_offset;
            } else {
                ElfW(Rel) *rel = reinterpret_cast<ElfW(Rel) *>(this->m_relplt_addr + sizeof(ElfW(Rel)) * i);
                r_info = (unsigned long)rel->r_info;
                r_offset = rel->r_offset;
            }

            if (elf_r_sym(r_info) == symidx && elf_r_type(r_info) == R_GENERIC_JUMP_SLOT) {
                void *addr = (void *) (this->get_bias_addr() + r_offset);
                if (!this->replace_function(addr, replace_func, old_func)) {
                    return false;
                }
                break;
            }
        }

        int reldyn_counts = this->get_is_use_rela() ? this->m_reldyn_bytes / sizeof(ElfW(Rela)) : this->m_reldyn_bytes / sizeof(ElfW(Rel));
        for (uint32_t i = 0; i < reldyn_counts; i++)
        {
            unsigned long r_info = 0;   // for Elf32 it's Elf32_Word, but Elf64 it's Elf64_Xword.
            ElfW(Addr) r_offset = 0;
            if (this->get_is_use_rela()) {
                ElfW(Rela) *rela = reinterpret_cast<ElfW(Rela) *>(this->m_reldyn_addr + sizeof(ElfW(Rela)) * i);
                r_info = (unsigned long)rela->r_info;
                r_offset = rela->r_offset;
            } else {
                ElfW(Rel) *rel = reinterpret_cast<ElfW(Rel) *>(this->m_reldyn_addr + sizeof(ElfW(Rel)) * i);
                r_info = (unsigned long)rel->r_info;
                r_offset = rel->r_offset;
            }

            if (elf_r_sym(r_info) == symidx &&
                    (elf_r_type(r_info) == R_GENERIC_ABS
                            || elf_r_type(r_info) == R_GENERIC_GLOB_DAT)) {

                void *addr = (void *) (this->get_bias_addr() + r_offset);
                if (!this->replace_function(addr, replace_func, old_func)) {
                    return false;
                }
            }
        }
        return true;
    }

    template<class T>
    void soimage::get_section_info(const char *name, ElfW(Shdr) **ppShdr, ElfW(Word) *pSize, T *data) {
        Elf32_Shdr *_shdr = this->find_section_by_name(name);

        if(_shdr) {
            SAFE_SET_VALUE(pSize, _shdr->sh_size / _shdr->sh_entsize);
            SAFE_SET_VALUE(data, reinterpret_cast<T>(this->get_bias_addr() + _shdr->sh_offset));
        } else {
            log_error("Could not found section %s\n", name);
        }

        SAFE_SET_VALUE(ppShdr, _shdr);
    }

    template<class T>
    void soimage::get_segment_info(const ElfW(Word) type, ElfW(Phdr) **ppPhdr, ElfW(Word) *pSize, T *data) {

        ElfW(Phdr)* _phdr = this->find_segment_by_type(type);
        if(_phdr) {
            SAFE_SET_VALUE(data, reinterpret_cast<T>(this->get_bias_addr() + _phdr->p_vaddr));
            SAFE_SET_VALUE(pSize, _phdr->p_memsz);
        } else {
            log_error("Could not found segment type is %d\n", type);
        }
        SAFE_SET_VALUE(ppPhdr, _phdr);
    }

    ElfW(Shdr)* soimage::find_section_by_name(const char *sname) {
        ElfW(Shdr) *target = NULL;
        ElfW(Shdr) *shdr = this->m_shdr;
        for(int i = 0; i < this->m_ehdr->e_shnum; i += 1) {
            const char *name = (const char *)(shdr[i].sh_name + this->m_shstr_ptr);
            if(!strncmp(name, sname, strlen(sname))) {
                target = (ElfW(Shdr)*)(shdr + i);
                break;
            }
        }
        return target;
    }

    ElfW(Phdr) *soimage::find_segment_by_type(const ElfW(Word) type) {
        ElfW(Phdr) *target = NULL;
        ElfW(Phdr) *phdr = this->m_phdr;

        for(int i = 0; i < this->m_ehdr->e_phnum; i += 1) {
            if(phdr[i].p_type == type) {
                target = phdr + i;
                break;
            }
        }
        return target;
    }


    uint32_t soimage::elf_hash(const char *name) {
        const unsigned char *tmp = (const unsigned char *) name;
        uint32_t h = 0, g;
        while (*tmp) {
            h = (h << 4) + *tmp++;
            g = h & 0xf0000000;
            h ^= g;
            h ^= g >> 24;
        }
        return h;
    }

    uint32_t soimage::gnu_hash (const char *s) {
        uint32_t h = 5381;
        for (unsigned char c = *s; c != '\0'; c = *++s) {
            h = h * 33 + c;
        }
        return h;
    }

    bool soimage::elf_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx) {
        ElfW(Sym) *target = NULL;

        if (!this->m_bucket || !this-> m_chain) {
            return false;
        }
        uint32_t hash = elf_hash(symbol);
        uint32_t index = this->m_bucket[hash % this->m_nbucket];

        if (!strcmp(this->m_symstr_ptr + this->m_sym_ptr[index].st_name, symbol)) {
            target = this->m_sym_ptr + index;
        }
        if (!target) {
            do {
                index = this->m_chain[index];
                if (!strcmp(this->m_symstr_ptr + this->m_sym_ptr[index].st_name, symbol)) {
                    target = this->m_sym_ptr + index;
                    break;
                }
            } while (index != 0);
        }
        if(target) {
            SAFE_SET_VALUE(sym, target);
            SAFE_SET_VALUE(symidx, index);
            return true;
        }
        return false;
    }

    bool soimage::gnu_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx) {
        uint32_t hash = this->gnu_hash(symbol);
        uint32_t h2 = hash >> this->m_gnu_shift2;
        uint32_t n = 0;

        if (!this->m_gnu_bloom_filter || !this->m_gnu_bucket || !this->m_gnu_chain) {
            return false;
        }

        uint32_t bloom_mask_bits = sizeof(ElfW(Addr))*8;
        uint32_t word_num = (hash / bloom_mask_bits) & this->m_gnu_maskwords;
        ElfW(Addr) bloom_word = this->m_gnu_bloom_filter[word_num];

        *sym = NULL;
        *symidx = 0;

        log_dbg("Search %s in %s@%p (gnu)\n",
                    symbol,
                    this->get_soname(),
                    reinterpret_cast<void*>(this->get_base_addr()));

        // test against bloom filter
        if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
            goto fail;
        }

        // bloom test says "probably yes"...
        n = this->m_gnu_bucket[hash % this->m_gnu_nbucket];

        if (n == 0) {
            goto fail;
        }

        do {
            ElfW(Sym)* s = this->m_sym_ptr + n;
            if (((this->m_gnu_chain[n] ^ hash) >> 1) == 0 &&
                        strcmp((this->m_symstr_ptr + s->st_name), symbol) == 0) {
                log_dbg("gnu_lookup Found %s in %s (%p) %zd\n",
                                symbol,
                                this->get_soname(),
                                reinterpret_cast<void*>(s->st_value),
                                static_cast<size_t>(s->st_size));
                *symidx = n;
                *sym = s;
                return true;
            }
        } while ((this->m_gnu_chain[n++] & 1) == 0);

    fail:
        // log_dbg("gnu_lookup NOT Found %s in %s@%p 3\n",
        //           symbol,
        //           this->get_soname(),
        //           reinterpret_cast<void*>(this->get_base_addr()));

        return false;
    }


    bool soimage::find_symbol_by_name(const char *symbol, ElfW(Sym) **sym, int *symidx) {
        if (!this->m_symstr_ptr || !this->m_sym_ptr) {
            log_warn("NOT symstr or symtab..\n");
            return false;
        }

        if (this->get_is_gnu_hash()) {
            bool result = this->gnu_lookup(symbol, sym, symidx);
            if (!result) {
                for(int i = 0; i < (int)this->m_gnu_symndx; i++) {
                    char const* symName = reinterpret_cast<char const *>(this->m_sym_ptr[i].st_name + this->m_symstr_ptr);
                    if (strcmp(symName, symbol) == 0) {
                        // found symbol
                        *symidx = i;
                        *sym = this->m_sym_ptr + i;
                        result = true;
                        log_info("Found %s in %s (%p) %zd\n",
                                    symbol,
                                    this->get_soname(),
                                    reinterpret_cast<void*>((*sym)->st_value),
                                    static_cast<size_t>((*sym)->st_size));
                    }
                }
            }
            // if (!result) {
            //     log_dbg("NOT Found %s in %s@%p\n",
            //         symbol,
            //         this->get_soname(),
            //         reinterpret_cast<void*>(this->get_base_addr()));
            // }
            return result;
        }
        return elf_lookup(symbol, sym, symidx);
    }

    bool soimage::replace_function(void* addr, void *replace_func, void **old_func) {
        bool ret_val = false;
        uint32_t old_prots = PROT_READ;
        uint32_t prots = old_prots;
        if(*(void **)addr == replace_func) {
            log_warn("addr %p had been replace.\n", addr);
            ret_val = true;
            goto fail;
        }

        if(!*old_func){
            *old_func = *(void **)addr;
        }

        if (get_mem_access(reinterpret_cast<ElfW(Addr)>(addr), &old_prots)) {
            log_error("read mem access fails, error %s.\n", strerror(errno));
            goto fail;
        }

        prots = old_prots | PROT_WRITE;
        if ((prots & PROT_WRITE) != 0) { // make sure we're never simultaneously writable / executable
            prots &= ~PROT_EXEC;
        }

        if(set_mem_access(reinterpret_cast<ElfW(Addr)>(addr), prots)) {
            log_error("modify mem access fails, error %s.\n", strerror(errno));
            goto fail;
        }

        *(void **)addr = replace_func;
        clear_cache(addr, getpagesize());
        log_info("[+] old_func is %p, replace_func is %p, new_func %p.\n", *old_func, replace_func, reinterpret_cast<void*>(*(void**)addr));
        ret_val = true;
    fail:
        return ret_val;
    }

    int soimage::set_mem_access(ElfW(Addr) addr, int prots) {
        void *page_start_addr = (void *)PAGE_START(addr);
        return mprotect(page_start_addr, getpagesize(), prots);
    }

    int soimage::get_mem_access(ElfW(Addr) addr, uint32_t* pprot) {
        int result = -1;

        const ElfW(Phdr)* phdr_table = this->m_phdr;
        const ElfW(Phdr)* phdr_end = phdr_table + this->m_ehdr->e_phnum;

        for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
            if (phdr->p_type == PT_LOAD) {
                ElfW(Addr) seg_start = this->get_bias_addr() + phdr->p_vaddr;
                ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

                ElfW(Addr) seg_page_start = PAGE_START(seg_start);
                ElfW(Addr) seg_page_end   = PAGE_END(seg_end);

                if (addr >= seg_page_start && addr < seg_page_end) {
                    *pprot = PFLAGS_TO_PROT(phdr->p_flags),
                    result = 0;
                }
            }
        }
        return result;
    }

    int soimage::clear_cache(void* addr, size_t len) {
        void *end = (uint8_t *)addr + len;
        return syscall(0xf0002, addr, end);
    }

    ElfW(Addr) soimage::get_exec_load_bias_addr(const ElfW(Ehdr)* ehdr) {
        ElfW(Addr) offset = ehdr->e_phoff;
        const ElfW(Phdr)* phdr_table = reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(ehdr) + offset);
        const ElfW(Phdr)* phdr_end = phdr_table + ehdr->e_phnum;

        for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
            if (phdr->p_type == PT_LOAD) {
                return reinterpret_cast<ElfW(Addr)>(ehdr) + phdr->p_offset - phdr->p_vaddr;
            }
        }
        return 0;
    }

    // dump 
    void soimage::dump_elf_header(void) {
        static char alpha_tab[17] = "0123456789ABCDEF";
        char buff[EI_NIDENT*3+1];

        ElfW(Ehdr)* ehdr = this->m_ehdr;

        log_info("Elf Header :\n");
        for(int i = 0; i < EI_NIDENT; i++) {
            uint8_t ch = ehdr->e_ident[i];
            buff[i*3 + 0] = alpha_tab[(int)((ch >> 4) & 0x0F)];
            buff[i*3 + 1] = alpha_tab[(int)(ch & 0x0F)];
            buff[i*3 + 2] = ' ';
        }
        buff[EI_NIDENT*3] = '\0';

        log_info("e_ident: %s\n",       buff);
        log_info("e_type: %x\n",        ehdr->e_type);
        log_info("e_machine: %x\n",     ehdr->e_machine);
        log_info("e_version: %x\n",     ehdr->e_version);
        log_info("e_entry: %lx\n",      (unsigned long)ehdr->e_entry);
        log_info("e_phoff: %lx\n",      (unsigned long)ehdr->e_phoff);
        log_info("e_shoff: %lx\n",      (unsigned long)ehdr->e_shoff);
        log_info("e_flags: %x\n",       ehdr->e_flags);
        log_info("e_ehsize: %x\n",      ehdr->e_ehsize);
        log_info("e_phentsize: %x\n",   ehdr->e_phentsize);
        log_info("e_phnum: %x\n",       ehdr->e_phnum);
        log_info("e_shentsize: %x\n",   ehdr->e_shentsize);
        log_info("e_shnum: %x\n",       ehdr->e_shnum);
        log_info("e_shstrndx: %x\n",    ehdr->e_shstrndx);
    }

    void soimage::dump_sections(void) {
        ElfW(Half) shnum = this->m_ehdr->e_shnum;
        ElfW(Shdr) *shdr = this->m_shdr;

        log_info("Sections shdr(%p) shnum(%d):\n", shdr, shnum);
        for(int i = 0; i < shnum; i += 1, shdr += 1) {
            const char *name = shdr->sh_name == 0 || !this->m_shstr_ptr ? "UNKOWN" :  (const char *)(shdr->sh_name + this->m_shstr_ptr);
            log_info("[%.2d] %-20s name(0x%08x);type(%x);addr(%lx);offset(%lx);entSize(%lx) \n", 
                                    i, 
                                    name, 
                                    shdr->sh_name,
                                    shdr->sh_type,
                                    (unsigned long)shdr->sh_addr,
                                    (unsigned long)shdr->sh_offset,
                                    (unsigned long)shdr->sh_entsize);
        }
    }
    void soimage::dump_segments(void) {
        ElfW(Phdr) *phdr = this->m_phdr;
        ElfW(Half) phnum = this->m_ehdr->e_phnum;

        log_info("Segments: \n");
        for(int i = 0; i < phnum; i++){
            log_info("[%.2d] %-.8x 0x%lx 0x%lx %lu %lu\n",
                     i,
                     phdr[i].p_type,
                     (unsigned long)phdr[i].p_vaddr,
                     (unsigned long)phdr[i].p_paddr,
                     (unsigned long)phdr[i].p_filesz,
                     (unsigned long)phdr[i].p_memsz);

        }
    }

    void soimage::dump_dynamics(void) {
        ElfW(Dyn) *dyn = this->m_dyn_ptr;
        log_info("Dynamic section info:\n");
        for(int i = 0; i < (int)this->m_dyn_size; i++) {
            const char * type = dynamic_tag_to_name(dyn[i].d_tag);
            log_info("[%.2d] %-14s 0x%016lx 0x%016lx\n",
                        i,
                        type,
                        (unsigned long)dyn[i].d_tag,
                        (unsigned long)dyn[i].d_un.d_val);
            if(dyn[i].d_tag == DT_NULL){
                break;
            }
        }
        return;
    }

    void soimage::dump_symbols(void) {
        ElfW(Sym) *sym = this->m_sym_ptr;
  
        log_dbg("m_gnu_symndx (%d), m_sym_size (%d)\n", this->m_gnu_symndx, this->m_sym_size);     
        log_info("dynsym section info: \n");
        if (this->get_is_gnu_hash()) {
            for(int i = 0; i < (int)this->m_gnu_symndx; i++) {
                log_info("[%2d] %-20s\n", i, sym[i].st_name + this->m_symstr_ptr);
            }
        } else {
            for(int i=0; i < (int)this->m_sym_size; i++) {
                log_info("[%2d] %-20s\n", i, sym[i].st_name + this->m_symstr_ptr);
            }
        }
        return;
    }

    void soimage::dump_rel_info(void) {
        ElfW(Rel)* rels[] = {reinterpret_cast<ElfW(Rel) *>(this->m_reldyn_addr), reinterpret_cast<ElfW(Rel) *>(this->m_relplt_addr)};
        ElfW(Word) resszs[] = {this->m_reldyn_bytes/sizeof(ElfW(Rel)), this->m_relplt_bytes/sizeof(ElfW(Rel))};

        ElfW(Sym) *sym = this->m_sym_ptr;

        log_info("rel section info:\n");
        for(int i = 0; i < (int)(sizeof(rels)/sizeof(rels[0])); i++) {
            ElfW(Rel) *rel = rels[i];
            ElfW(Word) relsz = resszs[i];

            for(int j = 0; j < (int)relsz; j += 1) {
                const char *name = sym[ELF32_R_SYM(rel[j].r_info)].st_name + this->m_symstr_ptr;
                log_info("[%.2d-%.4d] 0x%lx 0x%lx %-10s\n",
                                i, j,
                                (unsigned long)rel[j].r_offset,
                                (unsigned long)rel[j].r_info,
                                name);
            }
        }
        return;
    }

    void soimage::dump_rela_info(void) {
        ElfW(Rela)* relas[] = {reinterpret_cast<ElfW(Rela) *>(this->m_reldyn_addr), reinterpret_cast<ElfW(Rela) *>(this->m_relplt_addr)};
        ElfW(Word) resszs[] = {this->m_reldyn_bytes/sizeof(ElfW(Rela)), this->m_relplt_bytes/sizeof(ElfW(Rela))};

        ElfW(Sym) *sym = this->m_sym_ptr;

        log_info("rel section info:\n");
        for(int i = 0; i < (int)(sizeof(relas)/sizeof(relas[0])); i++) {
            ElfW(Rela) *rela = relas[i];
            ElfW(Word) relsz = resszs[i];

            for(int j = 0; j < (int)relsz; j += 1) {
                const char *name = sym[elf_r_sym(rela[j].r_info)].st_name + this->m_symstr_ptr;
                log_info("[%.2d-%.4d] 0x%lx 0x%lx 0x%ld %-10s\n",
                                i, j,
                                (unsigned long)rela[j].r_offset,
                                (unsigned long)rela[j].r_info,
                                (unsigned long)rela[j].r_addend,
                                name);
            }
        }
        return;
    }
};

