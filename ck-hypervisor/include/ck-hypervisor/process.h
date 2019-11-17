#pragma once

#include <atomic>
#include <ck-hypervisor/bqueue.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/network.h>
#include <ck-hypervisor/owned_message.h>
#include <ck-hypervisor/profile.h>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <stdint.h>
#include <stdlib.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <thread>
#include <unordered_set>
#include <vector>

using ck_pid_t = __uint128_t;

enum class TraceContinuationState {
  CONTINUE,
  BREAK,
};

enum class SandboxState {
  NONE,
  IN_EXEC,
  IN_SANDBOX,
};

using DeferredSyscallHandler = std::function<bool(user_regs_struct &)>;

struct RegisterDumpState {
  std::promise<user_regs_struct> sink;
  std::shared_future<void> completion;
};

class Process;

class Thread {
private:
  Process *process = nullptr;
  int os_tid = -1;
  std::unique_ptr<RegisterDumpState> register_dump_state;
  std::mutex register_dump_state_mu;

  Thread() {}
  void run_ptrace_monitor();
  TraceContinuationState handle_syscall(user_regs_struct regs, int &sig);
  TraceContinuationState handle_signal(user_regs_struct regs, int &sig);
  TraceContinuationState handle_new_thread();
  std::optional<std::string> read_c_string(unsigned long remote_addr,
                                           size_t max_size);
  bool read_memory(unsigned long remote_addr, size_t len, uint8_t *data);
  bool write_memory(unsigned long remote_addr, size_t len, const uint8_t *data);
  std::optional<std::vector<std::string>> read_string_vec(uint32_t count,
                                                          unsigned long rptr);

public:
  Thread(const Thread &that) = delete;
  Thread(Thread &&that) = delete;
  virtual ~Thread();

  static std::unique_ptr<Thread> from_os_thread(Process *process, int os_tid);
  static std::unique_ptr<Thread> first_thread(Process *process);

  void run();

  friend class Process;
};

class Process {
private:
  int os_pid;
  int socket;
  std::thread socket_listener;
  std::vector<std::function<void()>> awaiters;
  std::mutex awaiters_mu;
  BQueue<OwnedMessage> pending_messages;
  std::atomic<SandboxState> sandbox_state =
      std::atomic<SandboxState>(SandboxState::NONE);
  std::string image_type;
  std::mutex threads_mu;
  std::map<int, std::unique_ptr<Thread>> threads;
  std::filesystem::path storage_path, rootfs_path;
  std::shared_ptr<AppProfile> profile;
  std::shared_ptr<RootfsProfile> rootfs_profile;
  std::mutex ip_queue_mu;
  std::unique_ptr<SharedQueue> ip_recv_queue, ip_send_queue;
  std::thread ip_recv_queue_worker;

  void serve_sandbox();
  void handle_kernel_message(uint64_t session, MessageType tag, uint8_t *data,
                             size_t rem);

public:
  ck_pid_t ck_pid = 0, parent_ck_pid = 0;

  Process(std::shared_ptr<AppProfile> profile);
  Process(const Process &that) = delete;
  Process(Process &&that) = delete;
  virtual ~Process();

  void run();
  void run_as_child(int socket);
  void add_awaiter(std::function<void()> &&awaiter);
  void kill_async();
  bool has_capability(const char *cap);
  void input_ip_packet(uint8_t *header, size_t header_len,
                       volatile uint8_t *body, size_t body_len);

  friend class Thread;
};

class ProcessSet {
private:
  std::mutex mu;
  std::random_device pid_rand_dev;
  std::mt19937_64 pid_rand_gen;
  std::map<ck_pid_t, std::shared_ptr<Process>> processes;
  std::map<std::string, ck_pid_t> services;
  std::unordered_set<ck_pid_t> pending_termination;

  ck_pid_t next_pid_locked();

public:
  ProcessSet();
  ProcessSet(const ProcessSet &that) = delete;
  ProcessSet(ProcessSet &&that) = delete;
  virtual ~ProcessSet();

  ck_pid_t attach_process(std::shared_ptr<Process> proc);
  std::shared_ptr<Process> get_process(ck_pid_t pid);
  bool register_service(std::string &&name, ck_pid_t pid);
  std::optional<ck_pid_t> get_service(const char *name);
  void notify_termination(ck_pid_t pid);
  void tick();
  size_t get_num_processes();
  void for_each_process(std::function<bool(std::shared_ptr<Process> &)> f);
};

extern ProcessSet global_process_set;

bool read_process_memory(int pid, unsigned long remote_addr,
                                size_t len, uint8_t *data);
bool write_process_memory(int pid, unsigned long remote_addr,
                                 size_t len, const uint8_t *data);

static inline std::string stringify_ck_pid(ck_pid_t pid) {
  const uint8_t *pid_bytes = (const uint8_t *)&pid;
  char out[33];
  for (int i = 15; i >= 0; i--)
    sprintf(out + (15 - i) * 2, "%02x", pid_bytes[i]);
  return std::string(out, 32);
}
