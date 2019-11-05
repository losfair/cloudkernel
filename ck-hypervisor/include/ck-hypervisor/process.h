#pragma once

#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <random>
#include <stdlib.h>
#include <stdint.h>
#include <map>
#include <functional>
#include <optional>
#include <unordered_set>
#include <atomic>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/bqueue.h>
#include <ck-hypervisor/owned_message.h>

using ck_pid_t = __uint128_t;

enum class TraceContinuationState {
    CONTINUE,
    CLEANUP,
    BREAK,
};

class Process {
    private:
    int os_pid;
    int socket;
    std::thread socket_listener;
    std::thread ptrace_monitor;
    std::vector<std::function<void()>> awaiters;
    std::mutex awaiters_mu;
    BQueue<OwnedMessage> pending_messages;
    std::atomic<bool> kill_requested = std::atomic<bool>(false);
    std::atomic<bool> strict_mode = std::atomic<bool>(false);
    std::atomic<bool> record_mode = std::atomic<bool>(false);

    void serve_sandbox();
    void handle_kernel_message(uint64_t session, MessageType tag, uint8_t *data, size_t rem);
    void run_ptrace_monitor();
    TraceContinuationState handle_syscall(user_regs_struct regs, int& sig);
    TraceContinuationState handle_signal(user_regs_struct regs, int& sig);
    void run_as_child(int socket);
    bool inspect_mmap(unsigned long addr, size_t length, int prot, int flags, int fd, off_t offset);
    bool inspect_munmap(unsigned long addr, size_t length);

    public:
    std::vector<std::string> args;
    bool privileged = false;
    ck_pid_t ck_pid = 0, parent_ck_pid = 0;

    Process(const std::vector<std::string>& args);
    Process(const Process& that) = delete;
    Process(Process&& that) = delete;
    virtual ~Process();

    void run();
    void add_awaiter(std::function<void()>&& awaiter);
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
    ProcessSet(const ProcessSet& that) = delete;
    ProcessSet(ProcessSet&& that) = delete;
    virtual ~ProcessSet();

    ck_pid_t attach_process(std::shared_ptr<Process> proc);
    std::shared_ptr<Process> get_process(ck_pid_t pid);
    bool register_service(std::string&& name, ck_pid_t pid);
    std::optional<ck_pid_t> get_service(const char *name);
    void notify_termination(ck_pid_t pid);
    void tick();
};

extern ProcessSet global_process_set;

static inline std::string stringify_ck_pid(ck_pid_t pid) {
    const uint8_t *pid_bytes = (const uint8_t *) &pid;
    char out[33];
    for(int i = 15; i >= 0; i--) sprintf(out + (15 - i) * 2, "%02x", pid_bytes[i]);
    return std::string(out, 32);
}
