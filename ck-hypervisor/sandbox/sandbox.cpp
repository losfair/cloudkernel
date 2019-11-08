#include <ck-hypervisor/metadata.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/syscall.h>
#include <ck-hypervisor/file_base.h>
#include <ck-hypervisor/byteutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <iostream>
#include <signal.h>
#include <sys/ucontext.h>
#include <sys/socket.h>
#include <stdexcept>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <map>
#include <string>
#include <regex>
#include <memory>
#include <sys/ptrace.h>
#include <optional>
#include <assert.h>
#include <elf.h>
#include <sys/user.h>

#include "cc.h"
#include "snapshot_parser.h"

#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)

int hypervisor_fd = -1;
uint8_t __attribute__((aligned(16))) launchpad_stack[65536 * 16];

void debug_print(const char *text) {
    Message msg;
    msg.tag = MessageType::DEBUG_PRINT;
    msg.body = (const uint8_t *) text;
    msg.body_len = strlen(text);
    assert(msg.send(hypervisor_fd) >= 0);
}

static long __attribute__((naked)) report_hypervisor_fd(int fd) {
    asm(
        "movq $" _STR(CK_SYS_SET_REMOTE_HYPERVISOR_FD) ", %rax\n"
        "syscall\n"
        "ret\n"
    );
}

static long __attribute__((naked)) enter_sandbox_no_fdmap() {
    asm(
        "movq $" _STR(CK_SYS_ENTER_SANDBOX_NO_FDMAP) ", %rax\n"
        "syscall\n"
        "ret\n"
    );
}

static long __attribute__((naked)) enable_fdmap() {
    asm(
        "movq $" _STR(CK_SYS_ENABLE_FDMAP) ", %rax\n"
        "syscall\n"
        "ret\n"
    );
}

static void __attribute__((naked, noreturn)) invoke_noreturn_on_stack(void *stack, void *f, void *userdata) {
    asm(
        "movq %rdi, %rsp\n"
        "movq %rdx, %rdi\n"
        "pushq $0\n" // return address = nullptr
        "jmpq *%rsi\n"
    );
}

static long __attribute__((naked, noreturn)) load_processor_state_and_unmap_loader(user_regs_struct *regs) {
    asm(
        "movq $" _STR(CK_SYS_LOAD_PROCESSOR_STATE_AND_UNMAP_LOADER) ", %rax\n"
        "syscall\n"
        "ud2\n"
    );
}

struct SnapshotInvocationContext {
    int mfd;
    void *image_mapping;
    size_t image_size;
};

void invoke_snapshot(SnapshotInvocationContext *ctx) {
    user_regs_struct regs;
    load_snapshot(ctx->mfd, (const uint8_t *) ctx->image_mapping, ctx->image_size, regs); // `ctx` becomes invalid after this
    enable_fdmap();
    load_processor_state_and_unmap_loader(&regs);
}

struct MapInfo {
    std::string full_name;
    unsigned long size;
};

struct SharedModule {
    int mfd = -1;
    void *image_mapping = nullptr;
    std::string full_name;
    size_t image_size = 0;
    std::string module_type;

    SharedModule() {}
    SharedModule(const SharedModule& that) = delete;
    SharedModule(SharedModule&& that) = delete;

    virtual ~SharedModule() {
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

    void run(int argc, const char *argv[]) {
        if(module_type == "" || module_type == "elf") {
            std::stringstream ss;
            ss << "/proc/" << getpid() << "/fd/" << mfd;
            std::string mfd_path = ss.str();
            execv(mfd_path.c_str(), (char *const *) argv);
            std::cout << "execv() failed" << std::endl;
            abort();
        } else if(module_type == "snapshot") {
            enter_sandbox_no_fdmap();
            SnapshotInvocationContext ctx = {
                .mfd = mfd,
                .image_mapping = image_mapping,
                .image_size = image_size,
            };
            invoke_noreturn_on_stack((void *) (launchpad_stack + sizeof(launchpad_stack)), (void *) invoke_snapshot, (void *) &ctx);
        }
        abort();
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
            struct iovec parts[4];

            char module_type_buf[256] = {};

            parts[0].iov_base = (void *) &sender;
            parts[0].iov_len = sizeof(ck_pid_t);
            parts[1].iov_base = (void *) &session;
            parts[1].iov_len = sizeof(uint64_t);
            parts[2].iov_base = (void *) &raw_tag;
            parts[2].iov_len = sizeof(uint32_t);
            parts[3].iov_base = (void *) module_type_buf;
            parts[3].iov_len = sizeof(module_type_buf) - 1;
            int header_len = parts[0].iov_len + parts[1].iov_len + parts[2].iov_len;

            char c_buffer[256];

            struct msghdr msg = {
                .msg_iov = parts,
                .msg_iovlen = 4,
                .msg_control = c_buffer,
                .msg_controllen = sizeof(c_buffer),
            };

            size_t recv_len = recvmsg(hypervisor_fd, &msg, 0);

            if(recv_len < header_len) {
                throw std::runtime_error("unable to receive module message");
            }
            struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
            uint8_t *cdata = CMSG_DATA(cmsg);

            MessageType tag = (MessageType) raw_tag;
            if(tag == MessageType::TRIVIAL_RESULT) {
                throw std::runtime_error("module request rejected");
            } else if(tag == MessageType::MODULE_OFFER) {
                mfd = *((int*) cdata);
                this->full_name = full_name;
                this->module_type = std::string(module_type_buf);

                ssize_t image_size = _probe_image_size();
                if(image_size < 0) this->image_size = 0;
                else this->image_size = image_size;

                if(this->image_size == 0) throw std::runtime_error("!!! image_size is zero");

                image_mapping = mmap((void *) CK_LOADER_MMAP_BASE, this->image_size, PROT_READ, MAP_PRIVATE | MAP_FIXED, mfd, 0);
                if(image_mapping == MAP_FAILED) {
                    printf("MAP_FAILED: %s\n", strerror(errno));
                    throw std::runtime_error("failed to map image into memory");
                }
            } else {
                throw std::runtime_error("unexpected message type from hypervisor");
            }
        }
    }
};

static SharedModule init_mod;

int sandbox_run(int new_hypervisor_fd, int argc, const char *argv[]) {
    hypervisor_fd = new_hypervisor_fd;

    if(argc == 0) {
        std::cout << "No args" << std::endl;
        return 1;
    }

    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGSTOP);

    report_hypervisor_fd(hypervisor_fd);

    try {
        init_mod.fetch(argv[0]);
    } catch(std::runtime_error& e) {
        std::cout << "Fetch error: " << e.what() << std::endl;
        return 1;
    }

    init_mod.run(argc, argv);
    std::cout << "run_as_elf returned" << std::endl;
    return 1;
}

int main(int argc, const char *argv[]) {
    if(argc < 2) abort();

    const char *hypervisor_fd_s = getenv("CK_HYPERVISOR_FD");

    if(!hypervisor_fd_s) abort();

    int hypervisor_fd = atoi(hypervisor_fd_s);

    return sandbox_run(hypervisor_fd, argc - 1, &argv[1]);
}