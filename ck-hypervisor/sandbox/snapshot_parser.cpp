#include "snapshot_parser.h"
#include <unistd.h>
#include <sys/mman.h>
#include <ck-hypervisor/byteutils.h>
#include <ck-hypervisor/file_base.h>
#include <ck-hypervisor/snapshot_base.h>
#include <ck-hypervisor/syscall.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <string.h>
#include <sys/user.h>
#include <array>

#define _QUOTE(x) #x
#define _STR(x) _QUOTE(x)

static long __attribute__((naked)) enable_notify_invalid_syscall() {
    asm(
        "movq $" _STR(CK_SYS_NOTIFY_INVALID_SYSCALL) ", %rax\n"
        "syscall\n"
        "ret\n"
    );
}

int __attribute__((noinline)) load_snapshot(int mfd, const uint8_t *snapshot, size_t len, std::array<user_regs_struct, 1024>& regs_out) {
    size_t pos = 0;

    bool notify_invalid_syscall = read_vec<uint8_t>(snapshot, len, pos);

    uint32_t n_threads = read_vec<uint32_t>(snapshot, len, pos);
    if(n_threads > regs_out.size()) {
        throw std::runtime_error("too many threads");
    }
    for(uint32_t i = 0; i < n_threads; i++) {
        regs_out[i] = read_vec<user_regs_struct>(snapshot, len, pos);
    }

    uint32_t n_memory_ranges = read_vec<uint32_t>(snapshot, len, pos); 
    for(uint32_t i = 0; i < n_memory_ranges; i++) {
        auto start_addr = read_vec<uint64_t>(snapshot, len, pos);
        auto data_len = read_vec<uint32_t>(snapshot, len, pos);
        auto prot = read_vec<int32_t>(snapshot, len, pos);
        auto ty = (MemoryRangeType) read_vec<uint32_t>(snapshot, len, pos);
        auto data_offset = read_vec<uint64_t>(snapshot, len, pos);
        //printf("%lx %u %d %u\n", start_addr, data_len, prot, ty);

        switch(ty) {
            case MemoryRangeType::HEAP:
            case MemoryRangeType::DATA: {
                void *ptr = mmap((void *) start_addr, data_len, prot, MAP_PRIVATE | MAP_FIXED, mfd, data_offset);
                if(ptr == MAP_FAILED) {
                    printf("load_snapshot: unable to map memory at %p\n", (void *) start_addr);
                    throw std::runtime_error("load_snapshot: unable to map memory");
                }

                break;
            }
            //case MemoryRangeType::HEAP: break; // not supported
            case MemoryRangeType::STACK: {
                unsigned long stack_end = start_addr + (uint64_t) data_len;
                // touch stack
                for(uint64_t *p = ((uint64_t *) stack_end) - 1; p >= (uint64_t *) start_addr; p--) {
                    *p = 0;
                }
                std::copy(snapshot + data_offset, snapshot + data_offset + data_len, (uint8_t *) start_addr);
                break;
            }
            default: throw std::runtime_error("unknown memory range type");
        }
    }

    uint32_t n_files = read_vec<uint32_t>(snapshot, len, pos); 
    for(uint32_t i = 0; i < n_files; i++) {
        auto vfd = read_vec<int32_t>(snapshot, len, pos);
        auto path_len = read_vec<uint32_t>(snapshot, len, pos);
        std::string path; read_vec_n(snapshot, len, pos, path, path_len);
        auto offset = read_vec<uint64_t>(snapshot, len, pos);
        auto user = (bool) read_vec<uint32_t>(snapshot, len, pos);
        auto flags = read_vec<int32_t>(snapshot, len, pos);

        int fd = open(path.c_str(), flags);
        if(fd < 0) {
            printf("Warning: Unable to open file %s: %s\n", path.c_str(), strerror(errno));
            continue;
        }
        lseek(fd, offset, SEEK_SET);
        if(vfd != fd) {
            if(dup2(fd, vfd) < 0) {
                printf("Warning: Unable to duplicate fd\n");
            }
            close(fd);
        }
    }

    if(notify_invalid_syscall) {
        enable_notify_invalid_syscall();
    }

    return n_threads;
}
