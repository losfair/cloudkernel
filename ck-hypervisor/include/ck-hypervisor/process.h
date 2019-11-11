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
#include <ck-hypervisor/iomap.h>
#include <ck-hypervisor/snapshot.h>

using ck_pid_t = __uint128_t;

enum class TraceContinuationState {
    CONTINUE,
    BREAK,
};

enum class SandboxState {
    NONE,
    IN_EXEC,
    IN_SANDBOX_NO_FDMAP,
    IN_SANDBOX,
};

enum class SyscallFixupMethod {
    SET_VALUE,
    SEND_SIGSYS,
};

using DeferredSyscallHandler = std::function<bool(user_regs_struct&)>;

class Process;

class Thread {
    private:
    Process *process = nullptr;
    int os_tid = -1;

    Thread() {}
    void run_ptrace_monitor();
    bool register_returned_fd_after_syscall(user_regs_struct& regs, const std::filesystem::path& parent_path, const std::string& path);
    TraceContinuationState handle_syscall(user_regs_struct regs, int& sig);
    TraceContinuationState handle_signal(user_regs_struct regs, int& sig);
    TraceContinuationState handle_new_thread();
    std::optional<std::string> read_c_string(unsigned long remote_addr, size_t max_size);
    std::shared_ptr<FileDescription> map_fd_param0(
        user_regs_struct& regs,
        bool& is_invalid,
        SyscallFixupMethod& fixup_method,
        int64_t& replace_value,
        std::vector<DeferredSyscallHandler>& deferred,
        std::function<void(std::shared_ptr<FileDescription>&)> preprocess = nullptr
    );

    public:
    Thread(const Thread& that) = delete;
    Thread(Thread&& that) = delete;
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
    std::atomic<SandboxState> sandbox_state = std::atomic<SandboxState>(SandboxState::NONE);
    IOMap io_map;
    std::atomic<bool> notify_invalid_syscall = std::atomic<bool>(false);
    std::string image_type;
    std::mutex last_snapshot_mu;
    std::shared_ptr<std::vector<uint8_t>> last_snapshot;
    std::mutex threads_mu;
    std::map<int, std::unique_ptr<Thread>> threads;

    void serve_sandbox();
    void handle_kernel_message(uint64_t session, MessageType tag, uint8_t *data, size_t rem);
    void run_as_child(int socket);
    bool read_memory(unsigned long remote_addr, size_t len, uint8_t *data);
    template<class T> std::optional<T> read_memory_typed(unsigned long remote_addr) {
        static_assert(std::is_trivial<T>::value, "read_memory_typed only accepts trivial types");
        T ret;
        if(read_memory(remote_addr, sizeof(T), (uint8_t *) &ret)) return ret;
        else return std::nullopt;
    }
    bool write_memory(unsigned long remote_addr, size_t len, const uint8_t *data);
    template<class T> bool write_memory_typed(unsigned long remote_addr, const T& data) {
        static_assert(std::is_trivial<T>::value, "write_memory_typed only accepts trivial types");
        return write_memory(remote_addr, sizeof(T), (const uint8_t *) &data);
    }
    std::shared_ptr<std::vector<uint8_t>> take_snapshot();

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
    std::shared_ptr<std::vector<uint8_t>> get_last_snapshot() {
        std::lock_guard<std::mutex> lg(last_snapshot_mu);
        auto ret = last_snapshot;
        return ret;
    }

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
