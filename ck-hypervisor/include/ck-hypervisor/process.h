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
#include <ck-hypervisor/message.h>

using ck_pid_t = __uint128_t;

class Process {
    private:
    int os_pid;
    int socket;
    std::thread socket_listener;
    std::vector<std::function<void()>> awaiters;
    std::mutex awaiters_mu;

    void serve_sandbox();
    void handle_kernel_message(uint64_t session, MessageType tag, uint8_t *data, size_t rem);

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
    std::vector<ck_pid_t> pending_termination;

    ck_pid_t next_pid_locked();

    public:
    ProcessSet();
    ProcessSet(const ProcessSet& that) = delete;
    ProcessSet(ProcessSet&& that) = delete;
    virtual ~ProcessSet();

    ck_pid_t attach_process(std::shared_ptr<Process> proc);
    std::shared_ptr<Process> get_process(ck_pid_t pid);
    void notify_termination(ck_pid_t pid);
    void tick();
};

extern ProcessSet global_process_set;

static inline std::string stringify_ck_pid(ck_pid_t pid) {
    const uint8_t *pid_bytes = (const uint8_t *) &pid;
    char out[33];
    for(int i = 0; i < 16; i++) sprintf(out + i * 2, "%02x", pid_bytes[i]);
    return std::string(out, 32);
}
