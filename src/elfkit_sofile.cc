
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <assert.h>
#include <libgen.h>

#include "elfkit_common.h"
#include "elfkit_sofile.h"
#include "elfkit_soimage.h"

namespace elfkit {

    sofile::sofile() {
        this->m_phdr = nullptr;
        this->m_shdr = nullptr;
        this->m_dynamic  = nullptr;
        this->m_dynsym   = nullptr;
        this->m_symtab   = nullptr;
        this->m_dynstr   = nullptr;
        this->m_strtab   = nullptr;
        this->m_shstrtab = nullptr;
        this->m_dynamic_size  = 0;
        this->m_dynsym_size   = 0;
        this->m_symtab_size   = 0;
        this->m_dynstr_size   = 0;
        this->m_strtab_size   = 0;
        this->m_shstrtab_size = 0;
    }

    sofile::~sofile() {
        if (this->m_fd >= 0) {
            close(this->m_fd);
        }
    }

    bool sofile::load(const char * realpath) {
        int fd = open(realpath, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            log_error("open \"%s\" fail, error: %s", realpath, strerror(errno));
            return false;
        }
        struct stat file_stat;
        if (fstat(fd, &file_stat) < 0) {
            log_error("get \"%s\" filesz fail, error: %s", realpath, strerror(errno));
            return false;
        }

        this->m_file_size = file_stat.st_size;
        this->m_realpath = realpath;
        this->m_soname = basename(realpath);
        this->m_fd = fd;

        pread64(this->m_fd, &m_ehdr, sizeof(m_ehdr), 0);
        if (!soimage::check_is_elf_image((void *)&this->m_ehdr)) {
            log_error("%s check elf header fail.\n", this->get_realpath());
            return false;
        }
        if (!this->read_program_headers() ||
            !this->read_section_headers() || 
            !this->read_sections())  {
            return false;
        }
    }

    bool sofile::check_file_range(ElfW(Addr) offset, size_t size, size_t alignment) {
        off64_t range_start;
        off64_t range_end;
        return offset > 0 &&
            safe_add(&range_start, 0, offset) &&
            safe_add(&range_end, range_start, size) &&
            (range_start < m_file_size) &&
            (range_end <= m_file_size) &&
            ((offset % alignment) == 0);
    }

    bool sofile::read_program_headers() {
        this->m_phdr_num = m_ehdr.e_phnum;
        
        if (this->m_phdr_num == 0) {
            log_error("\"%s\" has no program headers", this->get_realpath());
            return false;
        }

        if (this->m_phdr_num < 1 || this->m_phdr_num > 65536/sizeof(ElfW(Phdr))) {
            log_error("\"%s\" has invalid e_phnum: %zd", this->get_soname(), this->m_phdr_num);
            return false;
        }

        // Boundary checks
        size_t size = this->m_phdr_num * sizeof(ElfW(Phdr));
        if (!check_file_range(this->m_ehdr.e_phoff, size, alignof(ElfW(Phdr)))) {
            log_error("\"%s\" has invalid phdr offset/size: %zu/%zu\n",
                    this->get_soname(),
                    static_cast<size_t>(this->m_ehdr.e_phoff),
                    size);
            return false;
        }
        if (!this->m_phdr_fragment.map(this->m_fd, 0, m_ehdr.e_phoff, size)) {
            log_error("\"%s\" phdr mmap failed: %s\n", this->get_realpath(), strerror(errno));
            return false;
        }

        this->m_phdr = static_cast<ElfW(Phdr)*>(m_phdr_fragment.data());
        return true;
    }

    bool sofile::read_section_headers() {
        this->m_shdr_num = this->m_ehdr.e_shnum;
        if (this->m_shdr_num == 0) {
            log_error("\"%s\" has no section headers\n", this->get_realpath());
            return false;
        }

        if (this->m_ehdr.e_shstrndx >= this->m_shdr_num) {
          log_error("\"%s\" section headers nums less than e_shstrndx\n", this->get_realpath());
            return false;
        }

        size_t size = this->m_shdr_num * sizeof(ElfW(Shdr));
        if (!check_file_range(this->m_ehdr.e_shoff, size, alignof(ElfW(Shdr)))) {
            log_error("\"%s\" has invalid shdr offset/size: %zu/%zu",
                      this->get_realpath(),
                      static_cast<size_t>(this->m_ehdr.e_shoff),
                      size);
            return false;
        }

        if (!this->m_shdr_fragment.map(this->m_fd, 0, this->m_ehdr.e_shoff, size)) {
            log_error("\"%s\" shdr mmap failed: %s", this->get_realpath(), strerror(errno));
            return false;
        }

        this->m_shdr = static_cast<ElfW(Shdr)*>(this->m_shdr_fragment.data());

        ElfW(Shdr) * shstrtab_shdr = &this->m_shdr[this->m_ehdr.e_shstrndx];
        if (!this->check_file_range(shstrtab_shdr->sh_offset, shstrtab_shdr->sh_size, 1)) {
           log_error("\"%s\" has invalid shdr offset/size: %zu/%zu",
                      this->get_realpath(),
                      static_cast<size_t>(this->m_ehdr.e_shoff),
                      size);
           return false;
        }
        if (!this->m_shstrtab_fragment.map(this->m_fd, 0, shstrtab_shdr->sh_offset, shstrtab_shdr->sh_size)) {
            log_error("\"%s\" shstrtab mmap failed: %s", this->get_realpath(), strerror(errno));
            return false;
        }
        this->m_shstrtab = static_cast<const char *>(this->m_shstrtab_fragment.data());
        this->m_shstrtab_size = shstrtab_shdr->sh_size;
    }

    bool sofile::read_sections() {

        ElfW(Shdr) * dynamic_shdr = nullptr;
        ElfW(Shdr) * dynsym_shdr = nullptr;
        ElfW(Shdr) * strtab_shdr = nullptr;
        ElfW(Shdr) * dynstr_shdr = nullptr;
        ElfW(Shdr) * symtab_shdr = nullptr;

        for (size_t i = 0; i < this->m_shdr_num; ++i) {
            const char * sh_name = &this->m_shstrtab[this->m_shdr[i].sh_name];
            log_dbg("%-30s %d\n", sh_name, this->m_shdr[i].sh_type);
            if (this->m_shdr[i].sh_type == SHT_DYNAMIC) {
                dynamic_shdr = &this->m_shdr[i];
            } else if (this->m_shdr[i].sh_type == SHT_DYNSYM) {
                dynsym_shdr = &this->m_shdr[i];
            } else if (this->m_shdr[i].sh_type == SHT_STRTAB) {
                if (strncmp(sh_name, ".strtab", 7) == 0) {
                    strtab_shdr = &this->m_shdr[i];
                } else if (strncmp(sh_name, ".dynstr", 7) == 0) {
                    dynstr_shdr = &this->m_shdr[i];
                }
            } else if (this->m_shdr[i].sh_type == SHT_SYMTAB) {
                if (strncmp(sh_name, ".symtab", 7) == 0) {
                    symtab_shdr = &this->m_shdr[i];
                }
            }
        }

        if (dynamic_shdr)
            log_dbg(".dynamic %p, %p, %zd\n", (void*)dynamic_shdr, (void*)dynamic_shdr->sh_offset, (size_t)dynamic_shdr->sh_size);
        if (dynsym_shdr)
            log_dbg(".dynsym  %p, %p, %zd\n", (void*)dynsym_shdr,  (void*)dynsym_shdr->sh_offset,  (size_t)dynsym_shdr->sh_size);
        if (dynstr_shdr)
            log_dbg(".dynstr  %p, %p, %zd\n", (void*)dynstr_shdr,  (void*)dynstr_shdr->sh_offset,  (size_t)dynstr_shdr->sh_size);
        if (symtab_shdr)
            log_dbg(".symtab  %p, %p, %zd\n", (void*)symtab_shdr,  (void*)symtab_shdr->sh_offset,  (size_t)symtab_shdr->sh_size);
        if (strtab_shdr)    
            log_dbg(".strtab  %p, %p, %zd\n", (void*)strtab_shdr,  (void*)strtab_shdr->sh_offset,  (size_t)strtab_shdr->sh_size);
        
        if (dynamic_shdr && 
            check_file_range(dynamic_shdr->sh_offset, dynamic_shdr->sh_size, alignof(ElfW(Dyn)))) {
            if (!this->m_dynamic_fragment.map(this->m_fd, 0, dynamic_shdr->sh_offset, dynamic_shdr->sh_size)) {
                log_warn("dynamic map fail, %s\n", strerror(errno));
            }
            this->m_dynamic = static_cast<ElfW(Dyn) *>(this->m_dynamic_fragment.data());
            this->m_dynamic_size = dynamic_shdr->sh_size;
        }
        if (dynsym_shdr && check_file_range(dynsym_shdr->sh_offset, dynsym_shdr->sh_size, alignof(ElfW(Sym)))) {
            if (!this->m_dynsym_fragment.map(this->m_fd, 0, dynsym_shdr->sh_offset, dynsym_shdr->sh_size) ) {
                log_warn("dynsym map fail, %s\n", strerror(errno));
            }
            this->m_dynsym = static_cast<ElfW(Sym) *>(this->m_dynsym_fragment.data());
            this->m_dynsym_size = dynsym_shdr->sh_size;
        }
        if (symtab_shdr && 
            check_file_range(symtab_shdr->sh_offset, symtab_shdr->sh_size, alignof(ElfW(Sym)))) {
            if (!this->m_symtab_fragment.map(this->m_fd, 0, symtab_shdr->sh_offset, symtab_shdr->sh_size)) {
                log_warn("symtab map fail, %s\n", strerror(errno));
            }
            this->m_symtab = static_cast<ElfW(Sym) *>(this->m_symtab_fragment.data());
            this->m_symtab_size = symtab_shdr->sh_size;
        }
        if (dynstr_shdr && 
            check_file_range(dynstr_shdr->sh_offset, dynstr_shdr->sh_size, 1)) {
            if (!this->m_dynstr_fragment.map(this->m_fd, 0, dynstr_shdr->sh_offset, dynstr_shdr->sh_size)) {
                log_warn("dynstr map fail, %s\n", strerror(errno));
            }
            this->m_dynstr = static_cast<const char *>(this->m_dynstr_fragment.data());
            this->m_dynstr_size = dynstr_shdr->sh_size;
        }
        if (strtab_shdr && 
            check_file_range(strtab_shdr->sh_offset, strtab_shdr->sh_size, 1)) {
            if (this->m_strtab_fragment.map(this->m_fd, 0, strtab_shdr->sh_offset, strtab_shdr->sh_size)) {
                log_warn("strtab map fail, %s\n", strerror(errno));
            }
            this->m_strtab = static_cast<const char *>(this->m_strtab_fragment.data());
            this->m_strtab_size = strtab_shdr->sh_size; 
        }
        return true;
    }

    ElfW(Sym) * find_symbol(const char * name, int type) {
        ElfW(Sym) * sym = this->m_symtab;
        const char * strtab = this->m_strtab;
        for (int i = 0; i < this->m_symtab_size/sizeof(ElfW(Sym)); i++) {
            const char * sym_name = sym[i].st_name + strtab;
            if (type == -1 || type == elf_r_type(sym[i].st_info)) {
                if (strcmp(name, sym_name) == 0) {
                    return sym;
                }
            }
        }
        return nullptr;
    }

    ElfW(Sym) * find_dynamic_symbol(const char * name, int type) {
        ElfW(Sym) * sym = this->m_dynsym;
        const char * strtab = this->m_dynstr;
        for (int i = 0; i < this->m_dynsym_size/sizeof(ElfW(Sym)); i++) {
            const char * sym_name = sym[i].st_name + strtab;
            if (type == -1 || type == elf_r_type(sym[i].st_info)) {
                if (strcmp(name, sym_name) == 0) {
                    return sym;
                }
            }
        }
        return nullptr;
    }

    void sofile::dump_elf_header(void) {
        static char alpha_tab[17] = "0123456789ABCDEF";
        char buff[EI_NIDENT*3+1];

        ElfW(Ehdr)* ehdr = &this->m_ehdr;

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

    void sofile::dump_section_headers(void) {
        log_info("Sections shdr_offset(%p) shnum(%d):\n", this->m_shdr, this->m_shdr_num);
        for(int i = 0; i < this->m_shdr_num; i += 1) {
            ElfW(Shdr) * shdr = &this->m_shdr[i];
            const char * name = shdr->sh_name == 0 || !this->m_shstrtab ? ".unknown" :  (const char *)(shdr->sh_name + this->m_shstrtab);
            log_info("[%.2d] %-20s name(0x%08x);type(%x);addr(%lx);offset(%lx);entSize(%lx) \n", 
                                    i, 
                                    name, 
                                    shdr->sh_name,
                                    shdr->sh_type,
                                    (unsigned long)shdr->sh_addr,
                                    (unsigned long)shdr->sh_offset,
                                    (unsigned long)shdr->sh_entsize);
        }
        return;
    }

    void sofile::dump_program_headers(void) {
        log_info("Programs phdr_offset(%p), phnum(%d): \n", this->m_phdr, this->m_phdr_num);
        for(int i = 0; i < this->m_phdr_num; i++) {
          ElfW(Phdr) *phdr = &this->m_phdr[i];
            log_info("[%.2d] %-.8x 0x%lx 0x%lx %lu %lu\n",
                     i,
                     phdr[i].p_type,
                     (unsigned long)phdr[i].p_vaddr,
                     (unsigned long)phdr[i].p_paddr,
                     (unsigned long)phdr[i].p_filesz,
                     (unsigned long)phdr[i].p_memsz);

        }
        return;
    }

    void sofile::dump_dynamics(void) {
        log_info("Dynamic section info:\n");
        ElfW(Dyn) * dyn = this->m_dynamic;
        for (int i = 0; i < this->m_dynamic_size/sizeof(ElfW(Dyn)); i++) {
            const char * type = dynamic_tag_to_name(dyn[i].d_tag);
            log_info("[%.2d] %-14s 0x%016lx 0x%016lx\n",
                        i,
                        type,
                        (unsigned long)dyn[i].d_tag,
                        (unsigned long)dyn[i].d_un.d_val);
            if (dyn[i].d_tag == DT_NULL) {
                break;
            }
        }
        return;
    }

    void sofile::dump_symbols(void) {
        log_info("Symbols: \n\tsymtab(%p), symtab_size(%d)\n", this->m_symtab, this->m_symtab_size);
        ElfW(Sym) * sym = this->m_symtab;
        const char * strtab = this->m_strtab;
        for (int i = 0; i < this->m_symtab_size/sizeof(ElfW(Sym)); i++) {
            const char * sym_name = sym[i].st_name + strtab;
            log_info("[%2d] %-20s st_value(%p), st_size(%d), info(%d), type(%d)\n", i, sym_name,
                    (void*)sym[i].st_value,
                    sym[i].st_size,
                    elf_r_sym(sym[i].st_info),
                    elf_r_type(sym[i].st_info));
        }
    }

    void sofile::dump_dynamic_symbols(void) {
        log_info("Dynamic symbols: \n\tdynsym(%p), dynsym_size(%d)\n", this->m_dynsym, this->m_dynsym_size);
        ElfW(Sym) * sym = this->m_dynsym;
        const char * strtab = this->m_dynstr;
        for (int i = 0; i < this->m_dynsym_size/sizeof(ElfW(Sym)); i++) {
            const char * sym_name = sym[i].st_name + strtab;
            log_info("[%2d] %-40s st_value(%p), st_size(%d), info(%d), type(%d)\n", i, sym_name,
                    (void*)sym[i].st_value,
                    sym[i].st_size,
                    elf_r_sym(sym[i].st_info),
                    elf_r_type(sym[i].st_info));
        }
    }  
};