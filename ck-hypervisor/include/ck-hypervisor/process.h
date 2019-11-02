#pragma once

#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <mutex>

class Process {
    private:
    std::mutex mu;
    int pid;
    int socket;
    std::thread socket_listener;

    public:
    bool no_kill_at_destruction = false;

    Process(const std::vector<std::string>& args);
    Process(const Process& that) = delete;
    Process(Process&& that) = delete;
    virtual ~Process();

    void serve_sandbox();
};
