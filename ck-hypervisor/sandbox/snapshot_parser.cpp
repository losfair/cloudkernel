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

#define _QUOTE(x) #x
#define _STR(x) _QUOTE(x)

static long __attribute__((naked)) attach_vfd(int vfd, int os_fd, FileInstanceType ty, const char *path) {
    asm(
        "movq $" _STR(CK_SYS_ATTACH_VFD) ", %rax\n"
        "syscall\n"
        "ret\n"
    );
}

static long __attribute__((naked)) enable_notify_invalid_syscall() {
    asm(
        "movq $" _STR(CK_SYS_NOTIFY_INVALID_SYSCALL) ", %rax\n"
        "syscall\n"
        "ret\n"
    );
}

void load_snapshot(const uint8_t *snapshot, size_t len, user_regs_struct& regs_out) {
    size_t pos = 0;

    bool notify_invalid_syscall = read_vec<uint8_t>(snapshot, len, pos);
    regs_out = read_vec<user_regs_struct>(snapshot, len, pos);

    uint32_t n_memory_ranges = read_vec<uint32_t>(snapshot, len, pos); 
    uint64_t last_start = 0, last_end = 0;
    for(uint32_t i = 0; i < n_memory_ranges; i++) {
        auto start_addr = read_vec<uint64_t>(snapshot, len, pos);
        auto data_len = read_vec<uint32_t>(snapshot, len, pos);
        auto prot = read_vec<int32_t>(snapshot, len, pos);
        auto ty = (MemoryRangeType) read_vec<uint32_t>(snapshot, len, pos);
        //printf("%lx %u %d %u\n", start_addr, data_len, prot, ty);

        switch(ty) {
            case MemoryRangeType::HEAP:
            case MemoryRangeType::DATA: {
                void *ptr = mmap((void *) start_addr, data_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
                if(ptr == MAP_FAILED) {
                    printf("load_snapshot: unable to map memory at %p\n", (void *) start_addr);
                    throw std::runtime_error("load_snapshot: unable to map memory");
                }

                read_vec_n(snapshot, len, pos, (uint8_t *) start_addr, data_len);

                if(mprotect(ptr, data_len, prot) != 0) {
                    printf("load_snapshot: unable to change protection at %p\n", (void *) start_addr);
                    throw std::runtime_error("load_snapshot: unable to change protection");
                }

                break;
            }/*
            case MemoryRangeType::HEAP: {
                printf("1\n");
                if(start_addr != last_end) {
                    throw std::runtime_error("load_snapshot: heap must start from the end address of data section");
                }
                printf("2\n");
                if(prctl(PR_SET_MM, PR_SET_MM_START_DATA, last_start, 0, 0) != 0) {
                    printf("%s\n", strerror(errno));
                    throw std::runtime_error("load_snapshot: PR_SET_MM_START_DATA failed");
                }
                printf("3\n");
                if(prctl(PR_SET_MM, PR_SET_MM_END_DATA, last_end, 0, 0) != 0) {
                    throw std::runtime_error("load_snapshot: PR_SET_MM_END_DATA failed");
                }
                printf("4\n");
                if(mmap((void *) start_addr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
                    printf("mmap on first heap page failed\n");
                    throw std::runtime_error("xxx");
                }
                if(prctl(PR_SET_MM, PR_SET_MM_START_BRK, start_addr + 4096, 0, 0) != 0) {
                    printf("%s\n", strerror(errno));
                    throw std::runtime_error("load_snapshot: PR_SET_MM_START_BRK failed");
                }
                printf("5\n");
                if(prctl(PR_SET_MM, PR_SET_MM_BRK, start_addr + (uint64_t) data_len, 0, 0) != 0) {
                    printf("%s\n", strerror(errno));
                    throw std::runtime_error("load_snapshot: PR_SET_MM_BRK failed");
                }
                printf("reading heap\n");
                read_vec_n(snapshot, len, pos, (uint8_t *) start_addr, data_len);
                printf("finished reading heap\n");
                break;
            }*/
            case MemoryRangeType::STACK: {
                unsigned long stack_end = start_addr + (uint64_t) data_len;
                // touch stack
                for(uint64_t *p = ((uint64_t *) stack_end) - 1; p >= (uint64_t *) start_addr; p--) {
                    *p = 0;
                } 
                read_vec_n(snapshot, len, pos, (uint8_t *) start_addr, data_len);
                break;
            }
            default: throw std::runtime_error("unknown memory range type");
        }

        last_start = start_addr;
        last_end = start_addr + (uint64_t) data_len;
    }

    uint32_t n_files = read_vec<uint32_t>(snapshot, len, pos); 
    for(uint32_t i = 0; i < n_files; i++) {
        auto vfd = read_vec<int32_t>(snapshot, len, pos);
        auto path_len = read_vec<uint32_t>(snapshot, len, pos);
        std::string path; read_vec_n(snapshot, len, pos, path, path_len);
        auto offset = read_vec<uint64_t>(snapshot, len, pos);
        auto ty = (FileInstanceType) read_vec<uint32_t>(snapshot, len, pos);
        auto flags = read_vec<int32_t>(snapshot, len, pos);

        switch(ty) {
            case FileInstanceType::IDMAP: break;
            case FileInstanceType::HYPERVISOR: break;
            case FileInstanceType::NORMAL: {
                int fd = open(path.c_str(), flags);
                if(fd < 0) {
                    printf("Warning: Unable to open file %s: %s\n", path.c_str(), strerror(errno));
                    break;
                }
                lseek(fd, offset, SEEK_SET);
                if(int err = attach_vfd(vfd, fd, ty, path.c_str()); err != 0) {
                    printf("Warning: Unable to attach vfd %d (os: %d) for path %s: %s\n", vfd, fd, path.c_str(), strerror(-err));
                    break;
                }
                break;
            }
            case FileInstanceType::USER: {
                if(int err = attach_vfd(vfd, -1, ty, nullptr); err != 0) {
                    printf("Warning: Unable to attach user vfd %d: %s\n", vfd, strerror(-err));
                    break;
                }
                break;
            }
            default: throw std::runtime_error("unknown file type");
        }
    }

    if(notify_invalid_syscall) {
        enable_notify_invalid_syscall();
    }
}
