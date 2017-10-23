#if !defined (__ELFKIT_MAPPED_FRAGMENT_H__)
#define __ELFKIT_MAPPED_FRAGMENT_H__

#include <elf.h>

#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>

namespace elfkit {
    class mapped_fragment {
    public:
        mapped_fragment();
        ~mapped_fragment();

        bool map(int fd, off64_t base_offset, size_t elf_offset, size_t size);

        void* data() const { return m_data; }
        size_t size() const { return m_size; }
        
    private:
        void* m_map_start;
        size_t m_map_size;
        void* m_data;
        size_t m_size;
    };
};

#endif