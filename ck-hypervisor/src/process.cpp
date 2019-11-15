#include <assert.h>
#include <chrono>
#include <ck-hypervisor/config.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/process_api.h>
#include <ck-hypervisor/registry.h>
#include <ck-hypervisor/syscall.h>
#include <fcntl.h>
#include <fstream>
#include <future>
#include <iostream>
#include <pthread.h>
#include <regex>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

static const bool permissive_mode = false;

void Process::run_as_child(int socket) {
  personality(ADDR_NO_RANDOMIZE); // snapshoting requires deterministic address
                                  // space layout
  if (socket != 3) {
    if (dup2(socket, 3) < 0) {
      printf("cannot duplicate socket fd\n");
      exit(1);
    }
    close(socket);
    socket = 3;
  }

  int flags = fcntl(socket, F_GETFD, 0);
  flags &= ~FD_CLOEXEC;
  if (fcntl(socket, F_SETFD, flags) < 0) {
    printf("unable to clear cloexec flag\n");
    exit(1);
  }

  std::vector<char *> args_exec;
  args_exec.push_back((char *)"ck-hypervisor-sandbox");
  for (auto &arg : args) {
    args_exec.push_back((char *)arg.c_str());
  }
  args_exec.push_back(nullptr);

  int sandbox_exec_fd = open("./ck-hypervisor-sandbox", O_RDONLY | O_CLOEXEC);
  if (sandbox_exec_fd < 0) {
    printf("unable to open sandbox executable\n");
    exit(1);
  }

  if (chroot(rootfs_path.c_str()) < 0) {
    printf("chroot() failed\n");
    exit(1);
  }

  if (mount("proc", "/proc", "proc", 0, nullptr) < 0) {
    printf("unable to mount /proc\n");
    exit(1);
  }

  if (setgid(65534) != 0 || setuid(65534) != 0) {
    printf("unable to drop permissions\n");
    if (getuid() == 0) {
      printf("cannot continue as root.\n");
      exit(1);
    }
  }
  char *envp[] = {nullptr};
  fexecve(sandbox_exec_fd, &args_exec[0], envp);
}

Process::Process(const std::vector<std::string> &new_args) {
  args = new_args;
  io_map.setup_defaults();
  pending_messages.set_capacity(1024);
}

static bool read_process_memory(int os_pid, unsigned long remote_addr,
                                size_t len, uint8_t *data) {
  if (len == 0)
    return true;

  iovec local_iov = {
      .iov_base = (void *)data,
      .iov_len = len,
  };
  iovec remote_iov = {
      .iov_base = (void *)remote_addr,
      .iov_len = len,
  };
  if (process_vm_readv(os_pid, &local_iov, 1, &remote_iov, 1, 0) != len)
    return false;
  else
    return true;
}

static bool write_process_memory(int os_pid, unsigned long remote_addr,
                                 size_t len, const uint8_t *data) {
  if (len == 0)
    return true;

  iovec local_iov = {
      .iov_base = (void *)data,
      .iov_len = len,
  };
  iovec remote_iov = {
      .iov_base = (void *)remote_addr,
      .iov_len = len,
  };
  if (process_vm_writev(os_pid, &local_iov, 1, &remote_iov, 1, 0) != len)
    return false;
  else
    return true;
}

static void print_regs(const user_regs_struct &regs) {
  printf("rax: %p\n", (void *)regs.rax);
  printf("rbx: %p\n", (void *)regs.rbx);
  printf("rcx: %p\n", (void *)regs.rcx);
  printf("rdx: %p\n", (void *)regs.rdx);
  printf("rdi: %p\n", (void *)regs.rdi);
  printf("rsi: %p\n", (void *)regs.rsi);
  printf("rsp: %p\n", (void *)regs.rsp);
  printf("rbp: %p\n", (void *)regs.rbp);
  printf("r8: %p\n", (void *)regs.r8);
  printf("r9: %p\n", (void *)regs.r9);
  printf("r10: %p\n", (void *)regs.r10);
  printf("r11: %p\n", (void *)regs.r11);
  printf("r12: %p\n", (void *)regs.r12);
  printf("r13: %p\n", (void *)regs.r13);
  printf("r14: %p\n", (void *)regs.r14);
  printf("r15: %p\n", (void *)regs.r15);
  printf("rip: %p\n", (void *)regs.rip);
  printf("fs_base: %p\n", (void *)regs.fs_base);
  printf("gs_base: %p\n", (void *)regs.gs_base);
}

bool Process::read_memory(unsigned long remote_addr, size_t len,
                          uint8_t *data) {
  return read_process_memory(os_pid, remote_addr, len, data);
}

bool Process::write_memory(unsigned long remote_addr, size_t len,
                           const uint8_t *data) {
  return write_process_memory(os_pid, remote_addr, len, data);
}

static int child_start(void *arg) {
  std::function<void()> *ctx = (std::function<void()> *)arg;
  (*ctx)();
  abort();
}

void Process::run() {
  int sockets[2];

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0) {
    throw std::runtime_error("unable to create socket pair");
  }

  storage_path = "/var/run";
  storage_path += "/ck-" + stringify_ck_pid(ck_pid);

  if (mkdir(storage_path.c_str(), 0755) < 0) {
    throw std::runtime_error("unable to create temporary storage");
  }

  rootfs_path = storage_path;
  rootfs_path += "/rootfs";

  if (mkdir(rootfs_path.c_str(), 0755) < 0) {
    throw std::runtime_error("unable to create rootfs");
  }

  procfs_path = rootfs_path;
  procfs_path += "/proc";

  if (mkdir(procfs_path.c_str(), 0755) < 0) {
    throw std::runtime_error("unable to create /proc mountpoint");
  }

  std::promise<void> child_pid;
  std::future<void> child_pid_fut = child_pid.get_future();

  // No exception may be thrown after this thread starts.
  std::thread([this, &child_pid, sockets]() {
    std::function<void()> child_fn = [this, sockets]() {
      close(sockets[0]);
      run_as_child(sockets[1]);
    };
    void *child_stack = nullptr;
    while (true) {
      child_stack = malloc(65536);
      if (child_stack)
        break;
      printf("malloc() failed, retrying\n");
      sleep(1);
    }

    int new_pid = -1;
    while (true) {
      new_pid = clone(child_start, (void *)((unsigned long)child_stack + 65536),
                      CLONE_NEWPID | CLONE_NEWNS | SIGCHLD, (void *)&child_fn);
      if (new_pid >= 0)
        break;
      printf("clone() failed, retrying\n");
      sleep(1);
    }

    free(child_stack);
    os_pid = new_pid;

    auto th = Thread::first_thread(this); // reads `os_pid`
    Thread *th_ref = &*th;
    {
      std::lock_guard<std::mutex> lg(threads_mu);
      threads[th->os_tid] = std::move(th);
    }

    // The new thread must have been inserted to `this->threads` before we can
    // allow `Process::run` to return, to ensure that the `Process` object has a
    // strictly longer lifetime than any thread it contains. Otherwise the
    // `Process` destructor might not observe the newly created thread, and
    // `Thread` will try to use a dangling pointer to access the process it
    // belongs to.
    child_pid.set_value();

    th_ref->run();
  }).detach();

  child_pid_fut.wait();
  close(sockets[1]);
  socket = sockets[0];

  socket_listener = std::thread([this]() {
    serve_sandbox();
    global_process_set.notify_termination(this->ck_pid);
  });
}

Process::~Process() {
  kill(os_pid, SIGKILL);
  waitpid(os_pid, nullptr, 0);

  pending_messages.close();
  socket_listener.join();

  // wait for all threads to terminate
  while (true) {
    {
      std::lock_guard<std::mutex> lg(threads_mu);
      if (threads.empty())
        break;
    }
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10ms);
  }

  close(socket);

  {
    std::lock_guard<std::mutex> lg(awaiters_mu);
    for (auto &f : awaiters)
      f();
  }

  if (fork() == 0) {
    umount2(procfs_path.c_str(), MNT_DETACH);
    execlp("rm", "rm", "-rf", storage_path.c_str(), nullptr);
    printf("unable to remove temporary storage directory\n");
    abort();
  }
}

void Process::add_awaiter(std::function<void()> &&awaiter) {
  std::lock_guard<std::mutex> lg(awaiters_mu);
  awaiters.push_back(std::move(awaiter));
}

static std::optional<std::vector<MemoryRangeSnapshot>>
take_memory_snapshot(int os_pid) {
  std::stringstream name_ss;
  name_ss << "/proc/" << os_pid << "/maps";
  std::string name = name_ss.str();

  std::ifstream maps(name.c_str());
  if (!maps) {
    return std::nullopt;
  }

  std::regex re(
      "([0-9a-f]+)-([0-9a-f]+) (....) ([0-9a-f]+) (..):(..) ([0-9]+)( *)(.*)");
  std::vector<MemoryRangeSnapshot> result;

  while (!maps.eof()) {
    std::string line;
    std::getline(maps, line);

    std::cmatch cm;
    if (!std::regex_match(line.c_str(), cm, re)) {
      break;
    } else {
      if (cm.size() != 10) {
        printf("take_memory_snapshot: unexpected match size\n");
        return std::nullopt;
      }

      uint64_t start = 0, end = 0;
      std::string perms = cm[3].str(), path = cm[9].str();

      {
        std::stringstream ss;
        ss << std::hex << cm[1];
        ss >> start;
      }
      {
        std::stringstream ss;
        ss << std::hex << cm[2];
        ss >> end;
      }

      if (end <= start) {
        printf("take_memory_snapshot: end <= start\n");
        return std::nullopt;
      }

      MemoryRangeSnapshot mss;
      mss.start = start;
      if (perms.size() != 4) {
        printf("take_memory_snapshot: unexpected 'perms' length\n");
        return std::nullopt;
      }
      if (perms[0] == 'r')
        mss.prot |= PROT_READ;
      if (perms[1] == 'w')
        mss.prot |= PROT_WRITE;
      if (perms[2] == 'x')
        mss.prot |= PROT_EXEC;

      if (path == "[vvar]" || path == "[vdso]" || path == "[vsyscall]") {
        continue; // do not dump these regions
      }

      if (path == "[heap]") {
        mss.ty = MemoryRangeType::HEAP;
      } else if (path == "[stack]") {
        mss.ty = MemoryRangeType::STACK;
      } else {
        mss.ty = MemoryRangeType::DATA;
      }

      mss.data_feed = [os_pid, start, end](uint8_t *out) {
        if (!read_process_memory(os_pid, start, end - start, out)) {
          printf("take_memory_snapshot: unable to read process memory from %lx "
                 "to %lx\n",
                 start, end);
          throw std::runtime_error(
              "take_memory_snapshot: unable to read process memory");
        }
      };
      mss.data_len = end - start;

      result.push_back(std::move(mss));
    }
  }

  return result;
}

std::shared_ptr<std::vector<uint8_t>> Process::take_snapshot() {
  ProcessSnapshot snapshot;

  snapshot.notify_invalid_syscall = this->notify_invalid_syscall.load();

  std::vector<std::future<std::optional<user_regs_struct>>> pending_regs;
  std::promise<void> completion;
  std::shared_future<void> completion_fut = completion.get_future().share();

  {
    std::lock_guard<std::mutex> lg(threads_mu);
    for (auto &[os_tid, th] : threads) {
      auto pending =
          std::unique_ptr<std::promise<std::optional<user_regs_struct>>>(
              new std::promise<std::optional<user_regs_struct>>);
      pending_regs.push_back(pending->get_future());

      std::promise<user_regs_struct> pending_l2;
      auto pending_l2_fut = std::unique_ptr<std::future<user_regs_struct>>(
          new std::future<user_regs_struct>(pending_l2.get_future()));

      {
        auto rds = std::unique_ptr<RegisterDumpState>(new RegisterDumpState);
        rds->sink = std::move(pending_l2);
        rds->completion = completion_fut;

        std::lock_guard<std::mutex> lg(th->register_dump_state_mu);
        th->register_dump_state = std::move(rds);
      }

      std::thread([pending_l2_fut(std::move(pending_l2_fut)),
                   pending(std::move(pending))]() {
        using namespace std::chrono_literals;
        auto status = pending_l2_fut->wait_for(1s);
        if (status == std::future_status::ready) {
          pending->set_value(pending_l2_fut->get());
        } else {
          pending->set_value(std::nullopt);
        }
      }).detach();

      tgkill(os_pid, os_tid, SIGTRAP);
    }
  }

  for (auto &fut : pending_regs) {
    if (auto maybe_regs = fut.get()) {
      auto regs = maybe_regs.value();
      snapshot.thread_regs.push_back(regs);
    } else {
      completion.set_value();
      return {};
    }
  }

  if (auto ss = take_memory_snapshot(os_pid)) {
    snapshot.memory = std::move(ss.value());
  } else {
    completion.set_value();
    return {};
  }

  snapshot.files = io_map.snapshot_files();

  completion.set_value();

  try {
    return std::shared_ptr<std::vector<uint8_t>>(
        new std::vector<uint8_t>(snapshot.serialize()));
  } catch (std::runtime_error &e) {
    return {};
  }
}

void Process::kill_async() { kill(os_pid, SIGKILL); }

void Process::serve_sandbox() {
  ck_pid_t recipient;
  uint64_t session;
  uint32_t raw_tag;
  std::vector<uint8_t> m_buf(MAX_MESSAGE_BODY_SIZE);

  struct iovec parts[4];
  parts[0].iov_base = (void *)&recipient;
  parts[0].iov_len = sizeof(ck_pid_t);
  parts[1].iov_base = (void *)&session;
  parts[1].iov_len = sizeof(uint64_t);
  parts[2].iov_base = (void *)&raw_tag;
  parts[2].iov_len = sizeof(uint32_t);
  parts[3].iov_base = &m_buf[0];
  parts[3].iov_len = m_buf.size();

  const int header_size =
      sizeof(ck_pid_t) + sizeof(uint64_t) + sizeof(uint32_t);

  while (true) {
    static const size_t num_fds = 8;
    char cmsg_buf[CMSG_SPACE(sizeof(int) * num_fds)] = {};
    struct msghdr msg = {
        .msg_iov = parts,
        .msg_iovlen = 4,
        .msg_control = (void *)cmsg_buf,
        .msg_controllen = sizeof(cmsg_buf),
    };
    ssize_t size = recvmsg(socket, &msg, MSG_CMSG_CLOEXEC);
    if (size < 0)
      break;

    auto recv_fds = std::unique_ptr<FdSet>(new FdSet);

    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
        continue;

      size_t payload_len = cmsg->cmsg_len - sizeof(cmsghdr);
      assert(payload_len % sizeof(int) == 0);
      size_t n_fds = payload_len / sizeof(int);

      int *cmsg_fds = (int *)CMSG_DATA(cmsg);
      for (int i = 0; i < n_fds; i++)
        recv_fds->add(cmsg_fds[i]);
    }

    if (size < header_size) {
      break;
    }
    size -= header_size;

    MessageType tag = (MessageType)raw_tag;
    if (recipient == 0) {
      handle_kernel_message(session, tag, &m_buf[0], size);
    } else {
      auto remote_proc = global_process_set.get_process(recipient);
      if (remote_proc) {
        OwnedMessage owned;
        owned.sender_or_recipient = this->ck_pid; // sender
        owned.session = session;
        owned.tag = tag;
        owned.body = std::vector<uint8_t>(&m_buf[0], &m_buf[size]);
        owned.fds = std::move(recv_fds);
        remote_proc->pending_messages.push(std::move(owned));
      }
    }
  }
}

Thread::~Thread() {}

std::unique_ptr<Thread> Thread::from_os_thread(Process *process, int os_tid) {
  auto ret = std::unique_ptr<Thread>(new Thread);
  ret->process = process;
  ret->os_tid = os_tid;
  return ret;
}

std::unique_ptr<Thread> Thread::first_thread(Process *process) {
  auto ret = std::unique_ptr<Thread>(new Thread);
  ret->process = process;
  ret->os_tid = process->os_pid;
  return ret;
}

std::optional<std::string> Thread::read_c_string(unsigned long remote_addr,
                                                 size_t max_size) {
  std::string s;
  while (true) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, os_tid, (void *)remote_addr, nullptr);
    if (errno)
      return std::nullopt;
    uint8_t *bytes = (uint8_t *)&word;
    for (int i = 0; i < sizeof(word); i++) {
      if (bytes[i] == 0)
        return s;
      if (s.size() == max_size)
        return std::nullopt;
      s.push_back(bytes[i]);
    }
    remote_addr += sizeof(word);
  }
}

void Thread::run() {
  try {
    run_ptrace_monitor();
  } catch (const std::runtime_error &e) {
    printf("ptrace monitor exited with error: %s\n", e.what());
  }
  // The `erase` operation can make `this` invalid. We need to defer it to end
  // of `run()`.
  std::unique_ptr<Thread> pending_delete;
  {
    std::lock_guard<std::mutex> lg(process->threads_mu);
    if (auto it = process->threads.find(os_tid); it != process->threads.end()) {
      // This is the ONLY place where `process->threads.erase` is allowed to
      // happen.
      pending_delete = std::move(it->second);
      process->threads.erase(it);
    } else {
      throw std::logic_error("Thread id not found in process->threads");
    }
  }
  if (os_tid == this->process->os_pid) {
    global_process_set.notify_termination(this->process->ck_pid);
  }
}

void Thread::run_ptrace_monitor() {
  int wstatus;
  if (waitpid(os_tid, &wstatus, 0) < 0)
    return;

  if (WSTOPSIG(wstatus) != SIGSTOP) {
    return;
  }

  if (ptrace(PTRACE_SETOPTIONS, os_tid, 0,
             PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP |
                 PTRACE_O_TRACECLONE) < 0) {
    printf("Unable to call ptrace() on sandbox thread.\n");
    return;
  }

  /*{
      auto ck_pid_s = stringify_ck_pid(process->ck_pid);
      printf("Monitor initialized on thread %d/%s\n", os_tid, ck_pid_s.c_str());
  }*/

  int stopsig = 0;

  while (true) {
    ptrace(PTRACE_CONT, os_tid, 0, stopsig);
    if (waitpid(os_tid, &wstatus, 0) < 0)
      break;

    // Normal exit or killed.
    if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
      break;
    }

    stopsig = WSTOPSIG(wstatus);

    user_regs_struct regs = {};
    ptrace(PTRACE_GETREGS, os_tid, 0, &regs);

    TraceContinuationState tcs = TraceContinuationState::BREAK;
    if ((wstatus >> 8) ==
        (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) { // system call
      stopsig = 0;
      tcs = handle_syscall(regs, stopsig);
      if (tcs == TraceContinuationState::CONTINUE && stopsig != 0) {
        tcs = handle_signal(regs, stopsig);
      }
    } else {
      tcs = handle_signal(regs, stopsig);
    }

    switch (tcs) {
    case TraceContinuationState::CONTINUE:
      break;
    case TraceContinuationState::BREAK:
      goto out;
    default:
      assert(false);
    }
  }

out:;

  /*{
      auto ck_pid_s = stringify_ck_pid(process->ck_pid);
      printf("Monitor exited on thread %d/%s\n", os_tid, ck_pid_s.c_str());
  }*/
}

bool Thread::register_returned_fd_after_syscall(
    user_regs_struct &regs, const std::filesystem::path &parent_path,
    const std::string &path, int flags) {
  if (regs.rax >= 0) {
    auto full_path = parent_path;
    full_path += path;
    process->insert_fd(regs.rax, full_path, flags);
  }

  return false; // is_invalid = false
}

TraceContinuationState Thread::handle_syscall(user_regs_struct regs,
                                              int &stopsig_out) {
  bool is_invalid = false;
  SyscallFixupMethod fixup_method = SyscallFixupMethod::SET_VALUE;
  long replace_value = -EPERM;

  long nr = regs.orig_rax;
  std::vector<DeferredSyscallHandler> deferred;

  if (process->sandbox_state.load() == SandboxState::NONE)
    switch (nr) {
    case __NR_execve: {
      process->sandbox_state.store(SandboxState::IN_EXEC);
      break;
    }
    case CK_SYS_ENTER_SANDBOX: {
      process->sandbox_state.store(SandboxState::IN_SANDBOX);
      is_invalid = true;
      fixup_method = SyscallFixupMethod::SET_VALUE;
      replace_value = 0;
      break;
    }
    default:
      break;
    }
  else
    switch (nr) {
    case __NR_socketpair:
      break; // TODO: Mark this process as not snapshotable

    case __NR_uname: {
      utsname ck_utsname = {
          .sysname = "Cloudkernel",
          .release = "0.0.1",
          .version = "0.0.1",
          .machine = "x86_64",
      };
      std::string pid_s = stringify_ck_pid(process->ck_pid);
      strncpy(ck_utsname.nodename, pid_s.c_str(),
              sizeof(ck_utsname.nodename) - 1);
      ck_utsname.nodename[sizeof(ck_utsname.nodename) - 1] = '\0';

      is_invalid = true;
      fixup_method = SyscallFixupMethod::SET_VALUE;
      if (process->write_memory(regs.rdi, sizeof(utsname),
                                (const uint8_t *)&ck_utsname))
        replace_value = 0;
      else
        replace_value = -EFAULT;
      break;
    }

    case __NR_dup3:
    case __NR_dup2:
    case __NR_dup: {
      auto desc = process->io_map.get_file_description(regs.rdi);
      if (!desc) {
        is_invalid = true;
        fixup_method = SyscallFixupMethod::SET_VALUE;
        replace_value = -EINVAL;
        break;
      }
      auto path = desc->path;
      int flags = desc->flags;
      if (nr == __NR_dup3)
        flags |= (int)regs.rdx;
      deferred.push_back(
          [this, path(std::move(path)), flags](user_regs_struct &regs) {
            if (regs.rax >= 0) {
              process->insert_fd(regs.rax, path, flags);
            }
            return false;
          });
      break;
    }

    case __NR_close: {
      int fd = regs.rdi;
      deferred.push_back([this, fd](user_regs_struct &regs) {
        if (regs.rax == 0) {
          process->io_map.remove_file_description(fd);
        }
        return false;
      });
      break;
    }

    // Only allow `clone` to create threads, but not full processes.
    case __NR_clone: {
      static const int allowed_flags =
          CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
          CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
          CLONE_CHILD_CLEARTID | CLONE_DETACHED;
      static const int required_flags = CLONE_VM | CLONE_THREAD;

      if ((regs.rdi & (~allowed_flags)) != 0 ||
          (regs.rdi & required_flags) != required_flags) {
        is_invalid = true;
        fixup_method = SyscallFixupMethod::SET_VALUE;
        replace_value = -EPERM;
        auto ck_pid_s = stringify_ck_pid(this->process->ck_pid);
        printf("Warning: Thread %d/%d/%s is trying to call clone() with "
               "disallowed flags.\n",
               this->process->os_pid, this->os_tid, ck_pid_s.c_str());
        break;
      } else {
      }
      break;
    }

    case __NR_openat: {
      if (auto desc = process->io_map.get_file_description(regs.rdi)) {
        if (auto maybe_path = read_c_string(regs.rsi, 65536)) {
          std::string path = std::move(maybe_path.value());
          int flags = regs.rdx;
          deferred.push_back([this, dirfd(std::move(desc)),
                              path(std::move(path)),
                              flags](user_regs_struct &regs) {
            return register_returned_fd_after_syscall(regs, dirfd->path, path,
                                                      flags);
          });
        } else {
          is_invalid = true;
          fixup_method = SyscallFixupMethod::SET_VALUE;
          replace_value = -EFAULT;
        }
      } else {
        is_invalid = true;
        fixup_method = SyscallFixupMethod::SET_VALUE;
        replace_value = -EINVAL;
      }
      break;
    }
    case __NR_open: {
      if (auto maybe_path = read_c_string(regs.rdi, 65536)) {
        std::string path = std::move(maybe_path.value());
        int flags = regs.rsi;
        deferred.push_back(
            [this, path(std::move(path)), flags](user_regs_struct &regs) {
              return register_returned_fd_after_syscall(regs, {}, path, flags);
            });
      } else {
        is_invalid = true;
        fixup_method = SyscallFixupMethod::SET_VALUE;
        replace_value = -EFAULT;
      }
      break;
    }

    case CK_SYS_GET_ABI_VERSION: {
      is_invalid = true;
      fixup_method = SyscallFixupMethod::SET_VALUE;
      replace_value = CK_ABI_VERSION;
      break;
    }
    case CK_SYS_NOTIFY_INVALID_SYSCALL: {
      process->notify_invalid_syscall.store(true);
      is_invalid = true;
      fixup_method = SyscallFixupMethod::SET_VALUE;
      replace_value = 0;
      break;
    }
    case CK_SYS_LOAD_PROCESSOR_STATE_AND_UNMAP_LOADER: {
      user_regs_struct new_regs;
      if (!process->read_memory(regs.rdi, sizeof(new_regs),
                                (uint8_t *)&new_regs)) {
        is_invalid = true;
        fixup_method = SyscallFixupMethod::SET_VALUE;
        replace_value = -EINVAL;
        break;
      }
      regs.orig_rax = __NR_munmap;
      regs.rdi = 0x70000000;
      regs.rsi = 0x10000000;
      ptrace(PTRACE_SETREGS, os_tid, 0, &regs);

      deferred.push_back([this, new_regs](user_regs_struct &regs) {
        // FIXME: Will all registers always be set to the provided value
        // successfully?
        ptrace(PTRACE_SETREGS, os_tid, 0, &new_regs);
        ptrace(PTRACE_GETREGS, os_tid, 0, &regs);
        return false;
      });
      break;
    }
    case CK_SYS_GETPID: {
      is_invalid = true;
      fixup_method = SyscallFixupMethod::SET_VALUE;

      __uint128_t pid = process->ck_pid;
      if (process->write_memory(regs.rdi, 16, (uint8_t *)&pid))
        replace_value = 0;
      else
        replace_value = -EFAULT;
      break;
    }
    case CK_SYS_DEBUG_PRINT_REGS: {
      is_invalid = true;
      fixup_method = SyscallFixupMethod::SET_VALUE;
      replace_value = 0;
      print_regs(regs);
      break;
    }
    default:
      if (permissive_mode) {
        auto ck_pid_s = stringify_ck_pid(this->process->ck_pid);
        printf("Warning (permissive mode): Process %d/%d/%s invoked an unknown "
               "syscall: %lu\n",
               this->process->os_pid, this->os_tid, ck_pid_s.c_str(), nr);
      } else {
        is_invalid = true;
        if (process->notify_invalid_syscall.load()) {
          fixup_method = SyscallFixupMethod::SEND_SIGSYS;
        } else {
          printf("Invalid syscall: %lu\n", nr);
          fixup_method = SyscallFixupMethod::SET_VALUE;
          replace_value = -EPERM;
        }
      }
      break;
    }

  if (is_invalid) {
    regs.orig_rax = __NR_getpid;
    ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
  }

  ptrace(PTRACE_SYSCALL, os_tid, 0, 0);
  int wstatus = 0;
  if (waitpid(os_tid, &wstatus, 0) < 0)
    return TraceContinuationState::BREAK;

  int stopsig = WSTOPSIG(wstatus);
  if (WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
    return TraceContinuationState::BREAK;
  }

  stopsig = WSTOPSIG(wstatus);
  ptrace(PTRACE_GETREGS, os_tid, 0, &regs);

  if (!is_invalid) {
    for (auto it = deferred.rbegin(); it != deferred.rend(); it++) {
      is_invalid = (*it)(regs);
      if (is_invalid) {
        fixup_method = SyscallFixupMethod::SEND_SIGSYS;
        break;
      }
    }
  }

  if ((wstatus >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
    return handle_new_thread();
  }

  if (stopsig == (SIGTRAP | 0x80)) {
    if (is_invalid) {
      switch (fixup_method) {
      case SyscallFixupMethod::SET_VALUE: {
        regs.rax = replace_value;
        ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
        break;
      }
      case SyscallFixupMethod::SEND_SIGSYS: {
        regs.rax = nr;
        ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
        tgkill(this->process->os_pid, this->os_tid, SIGSYS);
        break;
      }
      default:
        assert(false);
      }
    }
  } else {
    stopsig_out = stopsig;
  }

  return TraceContinuationState::CONTINUE;
}

TraceContinuationState Thread::handle_signal(user_regs_struct regs, int &sig) {
  if (sig == SIGTRAP &&
      this->process->sandbox_state.load() == SandboxState::IN_EXEC) {
    sig = 0;
    this->process->sandbox_state.store(SandboxState::IN_SANDBOX);
  } else if (sig == SIGTRAP) {
    std::unique_ptr<RegisterDumpState> rds;
    {
      std::lock_guard<std::mutex> lg(register_dump_state_mu);
      rds = std::move(register_dump_state);
    }
    if (rds) {
      sig = 0;
      rds->sink.set_value(regs);
      rds->completion.wait();
    }
  }
  return TraceContinuationState::CONTINUE;
}

TraceContinuationState Thread::handle_new_thread() {
  unsigned long new_tid = 0;
  if (ptrace(PTRACE_GETEVENTMSG, os_tid, 0, &new_tid) < 0) {
    printf("Unable to get message for CLONE event\n");
    return TraceContinuationState::BREAK;
  }
  assert(new_tid > 0);
  assert(waitpid(new_tid, nullptr, 0) >= 0);
  if (ptrace(PTRACE_DETACH, new_tid, 0, SIGSTOP) < 0) {
    printf("Unable to detach from the new thread\n");
    return TraceContinuationState::BREAK;
  }

  std::promise<void> creation_done;
  std::future<void> creation_done_fut = creation_done.get_future();
  std::thread([process(this->process), &creation_done, new_tid]() {
    if (ptrace(PTRACE_ATTACH, new_tid, 0, 0) < 0) {
      try {
        throw std::runtime_error("unable to attach to the new thread");
      } catch (...) {
        creation_done.set_exception(std::current_exception());
      }
      return;
    }
    auto th = Thread::from_os_thread(process, new_tid);
    Thread *th_ref = &*th;

    {
      std::lock_guard<std::mutex> lg(process->threads_mu);
      process->threads[th->os_tid] = std::move(th);
    }

    creation_done.set_value();
    th_ref->run();
  }).detach();

  try {
    creation_done_fut.get();
  } catch (std::runtime_error &e) {
    printf("Thread creation failed: %s\n", e.what());
  }
  return TraceContinuationState::CONTINUE;
}

void Process::insert_fd(int fd, const std::filesystem::path &path, int flags) {
  auto desc = std::shared_ptr<FileDescription>(new FileDescription);
  desc->path = path;
  desc->flags = flags;
  io_map.insert_file_description(fd, std::move(desc));
}

ProcessSet::ProcessSet() : pid_rand_gen(pid_rand_dev()) {}

ProcessSet::~ProcessSet() {}

ck_pid_t ProcessSet::next_pid_locked() {
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t lower = dist(pid_rand_gen), upper = dist(pid_rand_gen);
  return (((__uint128_t)lower) | (((__uint128_t)upper) << 64));
}

ck_pid_t ProcessSet::attach_process(std::shared_ptr<Process> proc) {
  std::lock_guard<std::mutex> lg(this->mu);

  auto pid = next_pid_locked();
  proc->ck_pid = pid;
  processes[pid] = std::move(proc);

  return pid;
}

std::shared_ptr<Process> ProcessSet::get_process(ck_pid_t pid) {
  std::lock_guard<std::mutex> lg(this->mu);
  auto it = processes.find(pid);
  if (it != processes.end())
    return it->second;
  else
    return std::shared_ptr<Process>();
}

bool ProcessSet::register_service(std::string &&name, ck_pid_t pid) {
  std::lock_guard<std::mutex> lg(this->mu);
  auto [it, inserted] = services.insert({std::move(name), pid});
  return inserted;
}

std::optional<ck_pid_t> ProcessSet::get_service(const char *name) {
  std::lock_guard<std::mutex> lg(this->mu);
  auto it = services.find(name);
  if (it != services.end()) {
    return it->second;
  } else {
    return std::nullopt;
  }
}

void ProcessSet::notify_termination(ck_pid_t pid) {
  std::lock_guard<std::mutex> lg(this->mu);
  pending_termination.insert(pid);
}

void ProcessSet::tick() {
  // Destructor calls are deferred to after releasing `this->mu` to prevent
  // deadlocking.
  std::vector<std::shared_ptr<Process>> deleted;

  {
    std::lock_guard<std::mutex> lg(this->mu);

    for (auto pid : pending_termination) {
      auto it = processes.find(pid);
      if (it != processes.end()) {
        deleted.push_back(it->second);
        processes.erase(it);
      }
    }

    pending_termination.clear();
  }
}

size_t ProcessSet::get_num_processes() {
  std::lock_guard<std::mutex> lg(this->mu);
  size_t ret = processes.size();
  return ret;
}

void ProcessSet::for_each_process(
    std::function<bool(std::shared_ptr<Process> &)> f) {
  std::lock_guard<std::mutex> lg(this->mu);
  for (auto &[pid, proc] : processes) {
    if (!f(proc))
      break;
  }
}

ProcessSet global_process_set;
