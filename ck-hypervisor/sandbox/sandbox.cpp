#include <ck-hypervisor/sandbox.h>
#include <ck-hypervisor/metadata.h>
#include <ck-hypervisor/message.h>
#include <stdio.h>
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

#include "kernel.h"

#define TEXT_BASE 0x3200000000ull
#define STACK_TOP 0x8000000000ull

static int hypervisor_fd = -1;
static unsigned long text_end = TEXT_BASE;

struct MapInfo {
    std::string full_name;
    unsigned long size;
};

static std::map<unsigned long, MapInfo> maps;

struct SharedModule {
    int mfd = -1;
    void *mapping = nullptr;
    ModuleMetadata metadata;
    std::string full_name;
    size_t image_size = 0;

    SharedModule() {}
    SharedModule(const SharedModule& that) = delete;
    SharedModule(SharedModule&& that) = delete;

    virtual ~SharedModule() {
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
        if(!mapping) throw std::runtime_error("mmap failed");

        MapInfo info;
        info.full_name = this->full_name;
        info.size = image_size;

        maps[(unsigned long) mapping] = info;
    }

    void fetch(const char *full_name) {
        size_t full_name_len = strlen(full_name);

        {
            std::vector<uint8_t> body(4 + full_name_len);
            * (uint32_t *) &body[0] = full_name_len;
            std::copy((const uint8_t *) full_name, (const uint8_t *) full_name + full_name_len, &body[4]);

            Message msg;
            msg.ty = MessageType::MODULE_REQUEST;
            msg.body = &body[0];
            msg.body_len = body.size();
            int ret = msg.send(hypervisor_fd);
        }

        {

            std::vector<uint8_t> m_buffer(65536);

            struct msghdr msg = {};
            struct iovec io = { .iov_base = &m_buffer[0], .iov_len = m_buffer.size() };
            msg.msg_iov = &io;
            msg.msg_iovlen = 1;

            char c_buffer[256];
            msg.msg_control = c_buffer;
            msg.msg_controllen = sizeof(c_buffer);
            ssize_t n_bytes = recvmsg(hypervisor_fd, &msg, 0);

            if (n_bytes <= 0) {
                throw std::runtime_error("unable to receive message from hypervisor");
            }

            struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);

            uint8_t *cdata = CMSG_DATA(cmsg);

            if(n_bytes < 4) {
                throw std::runtime_error("invalid data from hypervisor");
            }

            MessageType ty = (MessageType) (* (uint32_t *) &m_buffer[0]);
            if(ty == MessageType::MODULE_REJECT) {
                throw std::runtime_error("module request rejected");
            } else if(ty == MessageType::MODULE_OFFER) {
                if(n_bytes < 8) throw std::runtime_error("invalid module offer");
                int current = 8;
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
            printf("crosscall_resolve: %s\n", name);
            void **out = (void **) ucontext->uc_mcontext.gregs[REG_RSI];
            std::regex re("(.+)_([0-9]+).([0-9]+).([0-9]+)\\/(.+)");
            std::cmatch cm;
            if(!std::regex_match(name, cm, re) || cm.size() != 6) {
                printf("Invalid import name\n");
                abort();
            }
            std::string module_name = cm[1].str();
            if(module_name == "kernel") {
                // special case for kernel
                std::string func_name = cm[5].str();
                if(func_name == "DebugLog") {
                    *out = (void *) kDebugLog;
                    retval = (long) *out;
                } else {
                    abort();
                }
            } else {
                abort();
            }
            break;
        }
        default:
            printf("Unknown syscall: %d\n", syscall_id);
            break;
    }

    ucontext->uc_mcontext.gregs[REG_RAX] = retval;
}

void enforce_security_policies() {
    prctl(PR_SET_NO_NEW_PRIVS, 1);
    prctl(PR_SET_DUMPABLE, 0);

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_TRAP);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    //seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);

    if(seccomp_load(ctx) < 0) {
        std::cout << "unable to initialize seccomp" << std::endl;
        exit(1);
    }
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
    text_end += init_mod.image_size;

    void *start_addr = init_mod.resolve_symbol("_start");

    typedef int (*StartFunc)();
    StartFunc start_fn = (StartFunc) start_addr;
    std::cout << "start_address: " << (void *) start_fn << std::endl;

    enforce_security_policies();
    _exit(start_fn());

    return 0;
}

int main(int argc, const char *argv[]) {
    if(argc < 3) {
        abort();
    }
    int hypervisor_fd = atoi(argv[1]);
    return sandbox_run(hypervisor_fd, argc - 2, &argv[2]);
}