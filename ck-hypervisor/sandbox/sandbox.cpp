#include <assert.h>
#include <ck-hypervisor/byteutils.h>
#include <ck-hypervisor/file_base.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/metadata.h>
#include <ck-hypervisor/syscall.h>
#include <ck-hypervisor/round.h>
#include <elf.h>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <seccomp.h>
#include <signal.h>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/ucontext.h>
#include <sys/user.h>
#include <unistd.h>

#include "cc.h"
#include "snapshot_parser.h"

int hypervisor_fd = -1;
uint8_t __attribute__((aligned(16))) launchpad_stack[65536 * 16];
uint8_t *mmap_end = (uint8_t *)CK_LOADER_MMAP_BASE;

static long __attribute__((naked)) enter_sandbox() {
  asm("movq $" _STR(CK_SYS_ENTER_SANDBOX) ", %rax\n"
                                          "syscall\n"
                                          "ret\n");
}

static void __attribute__((naked, noreturn))
invoke_noreturn_on_stack(void *stack, void *f, void *userdata) {
  asm("movq %rdi, %rsp\n"
      "movq %rdx, %rdi\n"
      "pushq $0\n" // return address = nullptr
      "jmpq *%rsi\n");
}

static long __attribute__((naked, noreturn))
load_processor_state_and_unmap_loader(user_regs_struct *regs) {
  asm("movq $" _STR(CK_SYS_LOAD_PROCESSOR_STATE_AND_UNMAP_LOADER) ", %rax\n"
                                                                  "syscall\n"
                                                                  "ud2\n");
}

struct SnapshotInvocationContext {
  int mfd;
  void *image_mapping;
  size_t image_size;
};

// FIXME: Currently this does not handle multithreaded snapshots correctly.
void invoke_snapshot(SnapshotInvocationContext *ctx) {
  static std::array<user_regs_struct, 1024> thread_regs;
  int n_threads = load_snapshot(
      ctx->mfd, (const uint8_t *)ctx->image_mapping, ctx->image_size,
      thread_regs); // `ctx` becomes invalid after this
  for (int i = 1; i < n_threads; i++) {
    const int stack_size = 4096;
    void *stack = mmap((void *)mmap_end, stack_size, PROT_READ,
                       MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    if (stack == MAP_FAILED) {
      printf("STACK MAP FAILED\n");
      abort();
    }
    mmap_end += stack_size;
    if (clone((int (*)(void *))load_processor_state_and_unmap_loader, stack,
              CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
                  CLONE_SYSVSEM,
              (void *)&thread_regs[i]) < 0) {
      printf("CLONE FAILED\n");
      abort();
    }
  }
  load_processor_state_and_unmap_loader(&thread_regs[0]);
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
  SharedModule(const SharedModule &that) = delete;
  SharedModule(SharedModule &&that) = delete;

  virtual ~SharedModule() {
    if (mfd >= 0) {
      close(mfd);
    }
  }

  ssize_t _probe_image_size() {
    if (mfd == -1)
      return -1;

    lseek(mfd, 0, SEEK_END);
    ssize_t size = lseek(mfd, 0, SEEK_CUR);
    lseek(mfd, 0, SEEK_SET);

    return size;
  }

  void run(int argc, const char *argv[]) {
    if (module_type == "" || module_type == "elf") {
      std::stringstream ss;
      ss << "/proc/" << getpid() << "/fd/" << mfd;
      std::string mfd_path = ss.str();
      execv(mfd_path.c_str(), (char *const *)argv);
      std::cout << "execv() failed" << std::endl;
      _exit(1);
    } else if (module_type == "snapshot") {
      enter_sandbox();
      SnapshotInvocationContext ctx = {
          .mfd = mfd,
          .image_mapping = image_mapping,
          .image_size = image_size,
      };
      invoke_noreturn_on_stack(
          (void *)(launchpad_stack + sizeof(launchpad_stack)),
          (void *)invoke_snapshot, (void *)&ctx);
    }
    abort();
  }

  void fetch(const char *full_name) {
    {
      Message msg;
      msg.tag = MessageType::MODULE_REQUEST;
      msg.body = (const uint8_t *)full_name;
      msg.body_len = strlen(full_name);
      int ret = msg.send(hypervisor_fd);
      if (ret < 0) {
        throw std::runtime_error("unable to send module request message");
      }
    }

    {
      ck_pid_t sender;
      uint64_t session;
      uint32_t raw_tag;
      struct iovec parts[4];

      char module_type_buf[256] = {};

      parts[0].iov_base = (void *)&sender;
      parts[0].iov_len = sizeof(ck_pid_t);
      parts[1].iov_base = (void *)&session;
      parts[1].iov_len = sizeof(uint64_t);
      parts[2].iov_base = (void *)&raw_tag;
      parts[2].iov_len = sizeof(uint32_t);
      parts[3].iov_base = (void *)module_type_buf;
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

      if (recv_len < header_len) {
        throw std::runtime_error("unable to receive module message");
      }
      struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
      uint8_t *cdata = CMSG_DATA(cmsg);

      MessageType tag = (MessageType)raw_tag;
      if (tag == MessageType::TRIVIAL_RESULT) {
        throw std::runtime_error("module request rejected");
      } else if (tag == MessageType::MODULE_OFFER) {
        mfd = *((int *)cdata);
        this->full_name = full_name;
        this->module_type = std::string(module_type_buf);

        ssize_t image_size = _probe_image_size();
        if (image_size < 0)
          this->image_size = 0;
        else
          this->image_size = image_size;

        if (this->image_size == 0)
          throw std::runtime_error("!!! image_size is zero");

        image_mapping = mmap((void *)mmap_end, this->image_size, PROT_READ,
                             MAP_PRIVATE | MAP_FIXED, mfd, 0);
        if (image_mapping == MAP_FAILED) {
          printf("MAP_FAILED: %s\n", strerror(errno));
          throw std::runtime_error("failed to map image into memory");
        }
        mmap_end += round_up(this->image_size, 4096);
      } else {
        throw std::runtime_error("unexpected message type from hypervisor");
      }
    }
  }
};

static SharedModule init_mod;

#define SCMP_SETUP_FILE_IO(ctx, name)                                          \
  {                                                                            \
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), 1,                   \
                     SCMP_A0(SCMP_CMP_LE, 0x7fffffff));                        \
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(name), 1,                   \
                     SCMP_A0(SCMP_CMP_EQ, (unsigned long)AT_FDCWD));           \
    seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(name), 2,                    \
                     SCMP_A0(SCMP_CMP_GE, 0x80000000),                         \
                     SCMP_A0(SCMP_CMP_LE, 0xefffffff));                        \
  }

static void init_seccomp_rules() {
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_TRACE(1));

  // memory
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(madvise), 0);

  // signal handling
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sigaltstack), 0);

  // sleep
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clock_nanosleep), 0);

  // sync
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);

  // process
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(prctl), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(arch_prctl), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(restart_syscall), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_getaffinity), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(gettid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getegid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sched_yield), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);

  // random
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrandom), 0);

  // file metadata
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0);

  // General I/O.
  SCMP_SETUP_FILE_IO(ctx, lseek);
  SCMP_SETUP_FILE_IO(ctx, write);
  SCMP_SETUP_FILE_IO(ctx, read);
  SCMP_SETUP_FILE_IO(ctx, writev);
  SCMP_SETUP_FILE_IO(ctx, readv);
  SCMP_SETUP_FILE_IO(ctx, sendto);
  SCMP_SETUP_FILE_IO(ctx, recvfrom);
  SCMP_SETUP_FILE_IO(ctx, sendmsg);
  SCMP_SETUP_FILE_IO(ctx, recvmsg);
  SCMP_SETUP_FILE_IO(ctx, fstat);
  SCMP_SETUP_FILE_IO(ctx, fcntl);
  SCMP_SETUP_FILE_IO(ctx, readlinkat);
  SCMP_SETUP_FILE_IO(ctx, fadvise64);
  SCMP_SETUP_FILE_IO(ctx, newfstatat);
  SCMP_SETUP_FILE_IO(ctx, fsync);

  // Epoll.
  // epoll_create()/epoll_create1() invalidate the snapshot state.
  SCMP_SETUP_FILE_IO(ctx, epoll_wait);
  SCMP_SETUP_FILE_IO(ctx, epoll_ctl);
  SCMP_SETUP_FILE_IO(ctx, epoll_pwait);

  // Sockets.
  // socket() invalidates the snapshot state.
  SCMP_SETUP_FILE_IO(ctx, getsockopt);
  SCMP_SETUP_FILE_IO(ctx, setsockopt);
  SCMP_SETUP_FILE_IO(ctx, accept);
  SCMP_SETUP_FILE_IO(ctx, connect);
  SCMP_SETUP_FILE_IO(ctx, listen);
  SCMP_SETUP_FILE_IO(ctx, bind);
  SCMP_SETUP_FILE_IO(ctx, getsockname);
  SCMP_SETUP_FILE_IO(ctx, getpeername);

  // build and load the filter
  if (seccomp_load(ctx) < 0) {
    printf("failed to load seccomp filter\n");
    abort();
  }
  seccomp_release(ctx);
}

int sandbox_run(int new_hypervisor_fd, int argc, const char *argv[]) {
  hypervisor_fd = new_hypervisor_fd;

  if (argc == 0) {
    std::cout << "No args" << std::endl;
    return 1;
  }

  ptrace(PTRACE_TRACEME, 0, 0, 0);
  raise(SIGSTOP);

  init_seccomp_rules();

  try {
    init_mod.fetch(argv[0]);
  } catch (std::runtime_error &e) {
    std::cout << "Fetch error: " << e.what() << std::endl;
    return 1;
  }

  init_mod.run(argc, argv);
  std::cout << "run_as_elf returned" << std::endl;
  return 1;
}

int main(int argc, const char *argv[]) {
  if (argc < 2)
    abort();
  return sandbox_run(3, argc - 1, &argv[1]);
}