#include <ck-hypervisor/metadata.h>
#include <ck-hypervisor/message.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <iostream>
#include <signal.h>
#include <sys/ucontext.h>
#include <sys/socket.h>
#include <vector>
#include <stdexcept>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <map>
#include <string>
#include <regex>
#include <memory>

#include "cc.h"

int hypervisor_fd = -1;
unsigned long text_end = TEXT_BASE;
unsigned long mmap_end = MMAP_BASE;
bool sandbox_privileged = false;

struct MapInfo {
    std::string full_name;
    unsigned long size;
};

static std::map<unsigned long, MapInfo> maps;

struct SharedModule {
    int mfd = -1;
    void *mapping = nullptr;
    void *bss_mapping = nullptr;
    ModuleMetadata metadata;
    std::string full_name;
    size_t image_size = 0;
    size_t bss_size = 1048576ul * 16; // 16MB virtual memory for bss

    SharedModule() {}
    SharedModule(const SharedModule& that) = delete;
    SharedModule(SharedModule&& that) = delete;

    virtual ~SharedModule() {
        if(bss_mapping) munmap(bss_mapping, bss_size);
        if(mapping) {
            auto it = maps.find((unsigned long) mapping);
            if(it != maps.end()) {
                maps.erase(it);
            }
            munmap(mapping, image_size);
        }
        if(mfd >= 0) {
            close(mfd);
        }
    }

    ssize_t _probe_image_size() {
        if(mfd == -1) return -1;

        lseek(mfd, 0, SEEK_END);
        ssize_t size = lseek(mfd, 0, SEEK_CUR);
        lseek(mfd, 0, SEEK_SET);

        return size;
    }

    void * resolve_symbol(const char *name) {
        if(!mapping) return nullptr;

        for(auto& sym : metadata.symbols) {
            if(sym.name == name) {
                return (void *) ((unsigned long) mapping + (unsigned long) sym.addr);
            }
        }

        return nullptr;
    }

    void setup_mapping(void *base) {
        if(mfd == -1) throw std::runtime_error("invalid mfd");

        if(maps.find((unsigned long) base) != maps.end()) {
            throw std::runtime_error("duplicate mapping address");
        }

        mapping = mmap(base, image_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, mfd, 0);
        if(mapping == MAP_FAILED) throw std::runtime_error("mmap failed");

        bss_mapping = mmap((void *) ((uint8_t *) base + image_size), bss_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if(bss_mapping == MAP_FAILED) throw std::runtime_error("bss mmap failed");

        MapInfo info;
        info.full_name = this->full_name;
        info.size = image_size + bss_size;

        maps[(unsigned long) mapping] = info;
    }

    void fetch(const char *full_name) {
        {
            Message msg;
            msg.tag = MessageType::MODULE_REQUEST;
            msg.body = (const uint8_t *) full_name;
            msg.body_len = strlen(full_name);
            int ret = msg.send(hypervisor_fd);
            if(ret < 0) {
                throw std::runtime_error("unable to send module request message");
            }
        }

        {
            ck_pid_t sender;
            uint64_t session;
            uint32_t raw_tag;
            std::vector<uint8_t> m_buffer(MAX_MESSAGE_BODY_SIZE);
            struct iovec parts[4];

            parts[0].iov_base = (void *) &sender;
            parts[0].iov_len = sizeof(ck_pid_t);
            parts[1].iov_base = (void *) &session;
            parts[1].iov_len = sizeof(uint64_t);
            parts[2].iov_base = (void *) &raw_tag;
            parts[2].iov_len = sizeof(uint32_t);
            parts[3].iov_base = (void *) &m_buffer[0];
            parts[3].iov_len = m_buffer.size();

            int header_len = parts[0].iov_len + parts[1].iov_len + parts[2].iov_len;

            char c_buffer[256];

            struct msghdr msg = {
                .msg_iov = parts,
                .msg_iovlen = 4,
                .msg_control = c_buffer,
                .msg_controllen = sizeof(c_buffer),
            };

            ssize_t n_bytes = recvmsg(hypervisor_fd, &msg, 0);
            if(n_bytes < header_len) {
                throw std::runtime_error("unable to receive module message");
            }
            n_bytes -= header_len;

            struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
            uint8_t *cdata = CMSG_DATA(cmsg);

            MessageType tag = (MessageType) raw_tag;
            if(tag == MessageType::TRIVIAL_RESULT) {
                throw std::runtime_error("module request rejected");
            } else if(tag == MessageType::MODULE_OFFER) {
                int current = 0;
                metadata.parse([&](uint8_t *out, size_t n) -> int {
                    size_t n_copy = n_bytes - current < n ? n_bytes - current : n;
                    std::copy(&m_buffer[current], &m_buffer[current + n_copy], out);
                    current += n_copy;
                    return n_copy;
                });

                mfd = *((int*) cdata);

                this->full_name = full_name;

                ssize_t image_size = _probe_image_size();
                if(image_size < 0) this->image_size = 0;
                else this->image_size = image_size;
            } else {
                throw std::runtime_error("unexpected message type from hypervisor");
            }
        }
    }
};

static SharedModule init_mod;
static std::map<std::string, std::shared_ptr<SharedModule>> module_cache;


void handle_sigsys(int signum, siginfo_t *siginfo, ucontext_t *ucontext) {
    int syscall_id = (int) ucontext->uc_mcontext.gregs[REG_RAX];

    long retval = -EPERM;
    switch(syscall_id) {
        case 20000: {
            const char *name = (const char *) ucontext->uc_mcontext.gregs[REG_RDI];
            std::regex re("(.+)_([0-9]+).([0-9]+).([0-9]+)\\/(.+)");
            std::cmatch cm;
            if(!std::regex_match(name, cm, re) || cm.size() != 6) {
                abort();
            }
            std::string module_name = cm[1].str();
            if(module_name == "kernel") {
                // special case for kernel
                std::string func_name = cm[5].str();
                if(func_name == "SendMessage") {
                    retval = (long) kSendMessage;
                } else if(func_name == "RecvMessage") {
                    retval = (long) kRecvMessage;
                } else {
                    abort();
                }
            } else if(module_name == "user") {
                // special case for user
                std::string func_name = cm[5].str();
                if(func_name == "MapHeap") {
                    retval = (long) uMapHeap;
                } else {
                    abort();
                }
            } else {
                abort();
            }
            break;
        }
        default:
            //printf("Unknown syscall: %d\n", syscall_id);
            break;
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = retval;
}

void enforce_security_policies() {
    //prctl(PR_SET_NO_NEW_PRIVS, 1);
    //prctl(PR_SET_DUMPABLE, 0);

    scmp_filter_ctx ctx;

    if(sandbox_privileged) {
        std::cout << "Setting up privileged mode." << std::endl;
        ctx = seccomp_init(SCMP_ACT_ALLOW);
        seccomp_rule_add(ctx, SCMP_ACT_TRAP, 20000, 0);
    } else {
        ctx = seccomp_init(SCMP_ACT_TRAP);

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    }

    if(seccomp_load(ctx) < 0) {
        std::cout << "unable to initialize seccomp" << std::endl;
        exit(1);
    }
}

static unsigned long __attribute__((naked, noreturn)) enter_user_program(void *stack, int (*f)()) {
    asm(
        "mov %rdi, %rsp\n"
        "call *%rsi\n"
        "call _exit\n"
        "ud2\n"
    );
}

int sandbox_run(int new_hypervisor_fd, int argc, const char *argv[]) {
    hypervisor_fd = new_hypervisor_fd;
    signal(SIGSYS, (void (*) (int)) handle_sigsys);

    if(argc == 0) {
        std::cout << "No args" << std::endl;
        return 1;
    }
    
    try {
        init_mod.fetch(argv[0]);
    } catch(std::runtime_error& e) {
        std::cout << "Fetch error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "image_size: " << init_mod.image_size << std::endl;

    init_mod.setup_mapping((void *) text_end);
    text_end += init_mod.image_size + init_mod.bss_size;

    void *start_addr = init_mod.resolve_symbol("_start");

    typedef int (*StartFunc)();
    StartFunc start_fn = (StartFunc) start_addr;
    std::cout << "start_address: " << (void *) start_fn << std::endl;

    if(mmap((void *) (STACK_TOP - STACK_SIZE), STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0) == MAP_FAILED) {
        std::cout << "Unable to allocate stack" << std::endl;
        return 1;
    }

    enforce_security_policies();
    enter_user_program((void *) STACK_TOP, start_fn);
}

int main(int argc, const char *argv[]) {
    if(argc < 2) abort();

    const char *hypervisor_fd_s = getenv("CK_HYPERVISOR_FD");
    const char *privileged = getenv("CK_PRIVILEGED");

    if(!hypervisor_fd_s || !privileged) abort();

    int hypervisor_fd = atoi(hypervisor_fd_s);
    sandbox_privileged = strcmp(privileged, "1") == 0;

    return sandbox_run(hypervisor_fd, argc - 1, &argv[1]);
}