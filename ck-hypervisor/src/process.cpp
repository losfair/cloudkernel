#include <assert.h>
#include <chrono>
#include <ck-hypervisor/byteutils.h>
#include <ck-hypervisor/config.h>
#include <ck-hypervisor/external.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/network.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/process_api.h>
#include <ck-hypervisor/profile.h>
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
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

static int forked_setuid(uid_t uid) { return syscall(__NR_setuid, uid); }

static int forked_setgid(gid_t gid) { return syscall(__NR_setgid, gid); }

void Process::run_as_child(int socket) {
  if (socket != 3) {
    if (dup2(socket, 3) < 0) {
      printf("cannot duplicate socket fd\n");
      exit(1);
    }
    close(socket);
    socket = 3;
  }

  {
    int flags = fcntl(socket, F_GETFD, 0);
    flags &= ~FD_CLOEXEC;
    if (fcntl(socket, F_SETFD, flags) < 0) {
      printf("unable to clear cloexec flag on hypervisor socket\n");
      exit(1);
    }
  }

  std::vector<char *> args_exec;
  args_exec.push_back((char *)"ck-hypervisor-sandbox");
  for (auto &arg : profile->args) {
    args_exec.push_back((char *)arg.c_str());
  }
  args_exec.push_back(nullptr);

  int sandbox_exec_fd = open("./ck-hypervisor-sandbox", O_RDONLY | O_CLOEXEC);
  if (sandbox_exec_fd < 0) {
    printf("unable to open sandbox executable\n");
    exit(1);
  }

  int ckrt_fd = -1;
  if (global_profile.ckrt_path.size()) {
    ckrt_fd = open(global_profile.ckrt_path.c_str(), O_RDONLY); // inherit
    if (ckrt_fd < 0) {
      printf("unable to open ckrt\n");
      exit(1);
    }
  }

  Tun tun("access");
  if (forked_call_external("ip", {"ip", "link", "set", "access", "up"}) != 0 ||
      forked_call_external(
          "ip", {"ip", "route", "add", "default", "dev", "access"}) != 0 ||
      forked_call_external("ip", {"ip", "-6", "route", "add", "default", "dev",
                                  "access"}) != 0) {
    printf("unable to configure interface\n");
    exit(1);
  }
  if (profile->network && profile->network->ipv4_address) {
    auto addr = encode_ipv4_address(*profile->network->ipv4_address);
    if (forked_call_external(
            "ip", {"ip", "addr", "add", addr.c_str(), "dev", "access"}) != 0) {
      printf("unable to set ipv4 address\n");
      exit(1);
    }
  }
  if (profile->network && profile->network->ipv6_address) {
    auto addr = encode_ipv6_address(*profile->network->ipv6_address);
    if (forked_call_external("ip", {"ip", "-6", "addr", "add", addr.c_str(),
                                    "dev", "access"}) != 0) {
      printf("unable to set ipv6 address\n");
      exit(1);
    }
  }
  {
    int flags = fcntl(tun.fd, F_GETFD, 0);
    flags &= ~FD_CLOEXEC;
    if (fcntl(tun.fd, F_SETFD, flags) < 0) {
      printf("unable to clear cloexec flag on tun device\n");
      exit(1);
    }
  }

  for (auto &p : rootfs_profile->mounts) {
    unsigned long flags = 0;
    if (p.is_bind)
      flags |= MS_BIND;
    if (!p.is_bind && p.is_readonly)
      flags |= MS_RDONLY;

    std::filesystem::path target_path = rootfs_path;
    target_path += "/";
    target_path += p.target;

    if (mount(p.source.c_str(), target_path.c_str(), p.fstype.c_str(), flags,
              nullptr) < 0) {
      printf("mount() failed on path: %s\n", target_path.c_str());
      exit(1);
    }

    // remount is needed for readonly bind mounts to work
    if (p.is_bind && p.is_readonly) {
      flags |= MS_REMOUNT | MS_RDONLY;
      if (mount(p.source.c_str(), target_path.c_str(), p.fstype.c_str(), flags,
                nullptr) < 0) {
        printf("mount() (remount) failed on path: %s\n", target_path.c_str());
        exit(1);
      }
    }
  }

  if (chroot(rootfs_path.c_str()) < 0) {
    printf("chroot() failed\n");
    exit(1);
  }

  if (profile->workdir.size())
    chdir(profile->workdir.c_str());
  else
    chdir("/");

  if (forked_setgid(65534) != 0 || forked_setuid(65534) != 0) {
    printf("unable to drop permissions\n");
    exit(1);
  }

  std::vector<char *> envp;

  std::string tun_fd_s;
  {
    std::stringstream ss;
    ss << "CK_TUN=" << tun.fd;
    tun_fd_s = ss.str();
    envp.push_back(&tun_fd_s[0]);
  }

  std::string ld_preload_s;
  if (ckrt_fd >= 0) {
    std::stringstream ss;
    ss << "LD_PRELOAD=/proc/self/fd/" << ckrt_fd;
    ld_preload_s = ss.str();
    envp.push_back(&ld_preload_s[0]);
  }

  envp.push_back(nullptr);

  fexecve(sandbox_exec_fd, &args_exec[0], &envp[0]);
}

Process::Process(std::shared_ptr<AppProfile> profile) {
  pending_messages.set_capacity(1024);

  if (profile->args.size() == 0) {
    throw std::runtime_error("Process must receive at least one argument.");
  }
  this->profile = std::move(profile);

  {
    std::shared_lock<std::shared_mutex> lg(global_profile_mu);
    if (auto it =
            global_profile.rootfs_profiles.find(this->profile->rootfs_profile);
        it != global_profile.rootfs_profiles.end()) {
      this->rootfs_profile = it->second;
    } else {
      throw std::runtime_error("rootfs profile not found");
    }
  }
}

bool read_process_memory(int pid, unsigned long remote_addr,
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
  if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) != len)
    return false;
  else
    return true;
}

bool write_process_memory(int pid, unsigned long remote_addr,
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
  if (process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0) != len)
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

bool Thread::read_memory(unsigned long remote_addr, size_t len,
                          uint8_t *data) {
  return read_process_memory(os_tid, remote_addr, len, data);
}

bool Thread::write_memory(unsigned long remote_addr, size_t len,
                           const uint8_t *data) {
  return write_process_memory(os_tid, remote_addr, len, data);
}

static int child_start(void *arg) {
  std::function<void()> *ctx = (std::function<void()> *)arg;
  (*ctx)();
  abort();
}

static void insert_route(__uint128_t ck_pid, IPAddress unified_addr) {
  auto ep = std::shared_ptr<RoutingEndpoint>(new RoutingEndpoint);
  ep->ck_pid = ck_pid;
  ep->on_packet = [unified_addr, ck_pid](uint8_t *header, size_t header_len,
                                         volatile uint8_t *body,
                                         size_t body_len) {
    if (auto proc = global_process_set.get_process(ck_pid)) {
      proc->input_ip_packet(header, header_len, body, body_len);
    } else {
      global_router.unregister_route(unified_addr, ck_pid);
    }
  };
  global_router.register_route(unified_addr, std::move(ep));
}

void Process::input_ip_packet(uint8_t *header, size_t header_len,
                              volatile uint8_t *body, size_t body_len) {
  std::lock_guard<std::mutex> lg(ip_queue_mu);
  if (ip_send_queue && ip_send_queue->can_push()) {
    uint8_t *place = ip_send_queue->get_data_ptr();
    size_t remain_cap = SharedQueue::data_size();

    if (remain_cap < header_len)
      return;
    remain_cap -= header_len;
    std::copy(header, header + header_len, place);

    size_t body_send_len = body_len < remain_cap ? body_len : remain_cap;
    std::copy(body, body + body_send_len, place + header_len);
    ip_send_queue->push(header_len + body_send_len);
  }
  // drop otherwise
}

void Process::run() {
  if (profile->network) {
    if (profile->network->ipv4_address) {
      __uint128_t unified_addr = ((__uint128_t)0xffff00000000ull) |
                                 (__uint128_t)*profile->network->ipv4_address;
      insert_route(ck_pid, unified_addr);
      add_awaiter([ck_pid(this->ck_pid), unified_addr]() {
        global_router.unregister_route(unified_addr, ck_pid);
      });
    }
    if (profile->network->ipv6_address) {
      insert_route(ck_pid, *profile->network->ipv6_address);
      add_awaiter([ck_pid(this->ck_pid),
                   unified_addr(*profile->network->ipv6_address)]() {
        global_router.unregister_route(unified_addr, ck_pid);
      });
    }
  }

  int sockets[2];

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0) {
    throw std::runtime_error("unable to create socket pair");
  }

  storage_path = "/var/run";
  storage_path /= "ck-" + stringify_ck_pid(ck_pid);

  if (mkdir(storage_path.c_str(), 0755) < 0) {
    throw std::runtime_error("unable to create temporary storage");
  }

  rootfs_path = storage_path / "rootfs";

  if (mkdir(rootfs_path.c_str(), 0755) < 0) {
    throw std::runtime_error("unable to create rootfs");
  }

  for (auto &p : rootfs_profile->mounts) {
    auto path = rootfs_path;
    path += "/";
    path += p.target;
    if (mkdir(path.c_str(), 0755) < 0) {
      printf("Mountpoint creation failed: %s\n", path.c_str());
      throw std::runtime_error("unable to create mountpoint");
    }
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
                      CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD,
                      (void *)&child_fn);
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
    std::lock_guard<std::mutex> lg(ip_queue_mu);
    if (ip_recv_queue) {
      ip_recv_queue->request_termination();
      ip_recv_queue_worker.join();
    }
  }

  {
    std::lock_guard<std::mutex> lg(awaiters_mu);
    for (auto &f : awaiters)
      f();
  }

  for (auto &p : rootfs_profile->mounts) {
    auto path = rootfs_path;
    path += "/";
    path += p.target;
    if (umount2(path.c_str(), MNT_DETACH) < 0) {
      printf("Warning: umount2() failed on path: %s\n", path.c_str());
    }
  }

  if (call_external("rm", {"rm", "-rf", storage_path.c_str()}) != 0) {
    printf("Warning: Unable to remove temporary storage at %s\n",
           storage_path.c_str());
  }
}

void Process::add_awaiter(std::function<void()> &&awaiter) {
  std::lock_guard<std::mutex> lg(awaiters_mu);
  awaiters.push_back(std::move(awaiter));
}

void Process::kill_async() { kill(os_pid, SIGKILL); }

bool Process::has_capability(const char *cap) {
  return profile->capabilities.find(cap) != profile->capabilities.end();
}

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

TraceContinuationState Thread::handle_syscall(user_regs_struct regs,
                                              int &stopsig_out) {
  bool is_invalid = false;
  long replace_value = -EPERM;

  long nr = regs.orig_rax;
  std::vector<DeferredSyscallHandler> deferred;

  if (process->sandbox_state.load() == SandboxState::NONE)
    switch (nr) {
    case __NR_execve: {
      process->sandbox_state.store(SandboxState::IN_EXEC);
      break;
    }
    default:
      break;
    }
  else
    switch (nr) {
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
      if (write_memory(regs.rdi, sizeof(utsname),
                                (const uint8_t *)&ck_utsname))
        replace_value = 0;
      else
        replace_value = -EFAULT;
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

    case CK_SYS_GET_ABI_VERSION: {
      is_invalid = true;
      replace_value = CK_ABI_VERSION;
      break;
    }
    case CK_SYS_GETPID: {
      is_invalid = true;

      __uint128_t pid = process->ck_pid;
      if (write_memory(regs.rdi, 16, (uint8_t *)&pid))
        replace_value = 0;
      else
        replace_value = -EFAULT;
      break;
    }
    case CK_SYS_DEBUG_PRINT_REGS: {
      is_invalid = true;
      replace_value = 0;
      print_regs(regs);
      break;
    }
    default:
      is_invalid = true;
      printf("Invalid syscall: %lu\n", nr);
      replace_value = -EPERM;
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
        break;
      }
    }
  }

  if ((wstatus >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
    return handle_new_thread();
  }

  if (stopsig == (SIGTRAP | 0x80)) {
    if (is_invalid) {
      regs.rax = replace_value;
      ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
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
