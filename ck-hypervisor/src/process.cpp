#include <ck-hypervisor/process.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <iostream>
#include <thread>
#include <future>
#include <signal.h>
#include <string.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/registry.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/config.h>
#include <ck-hypervisor/process_api.h>
#include <regex>
#include <pthread.h>

static int send_ok(int socket) {
    uint32_t buf = (uint32_t) MessageType::OK;
    return send(socket, (void *) &buf, sizeof(buf), 0);
}

static int send_reject(int socket) {
    uint32_t buf = (uint32_t) MessageType::REJECT;
    return send(socket, (void *) &buf, sizeof(buf), 0);
}

static int send_reject(int socket, const char *reason, size_t reason_len) {
    std::vector<std::uint8_t> buf(4 + reason_len);
    * (uint32_t *) &buf[0] = (uint32_t) MessageType::REJECT;
    std::copy((const uint8_t *) reason, (const uint8_t *) reason + reason_len, &buf[4]);
    return send(socket, (void *) &buf[0], buf.size(), 0);
}

static int send_reject(int socket, const char *reason) {
    return send_reject(socket, reason, strlen(reason));
}

Process::Process(const std::vector<std::string>& new_args) {
    args = new_args;
}

void Process::run() {
    int sockets[2];

    if(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0) {
        throw std::runtime_error("unable to create socket pair");
    }

    int new_pid = fork();
    if(new_pid < 0) throw std::runtime_error("unable to create process");

    if(new_pid == 0) {
        close(sockets[0]);
        std::stringstream ss;
        ss << sockets[1];
        auto socket_id_str = ss.str();

        int flags = fcntl(sockets[1], F_GETFD, 0);
        flags &= ~FD_CLOEXEC;
        if(fcntl(sockets[1], F_SETFD, flags) < 0) {
            std::cout << "unable to clear cloexec" << std::endl;
            exit(1);
        }

        std::vector<char *> args_exec;
        args_exec.push_back((char *) "ck-hypervisor-sandbox");
        args_exec.push_back((char *) socket_id_str.c_str());
        for(auto& arg : args) {
            args_exec.push_back((char *) arg.c_str());
        }
        args_exec.push_back(nullptr);

        if(setgid(65534) != 0 || setuid(65534) != 0) {
            std::cout << "unable to drop permissions" << std::endl;
            if(getuid() == 0) {
                std::cout << "cannot continue as root." << std::endl;
                exit(1);
            }
        }
        execv("./ck-hypervisor-sandbox", &args_exec[0]);
        exit(1);
    } else {
        close(sockets[1]);
        socket = sockets[0];
        os_pid = new_pid;

        socket_listener = std::thread([this]() {
            serve_sandbox();
            global_process_set.notify_termination(this->ck_pid);
        });
    }
}

Process::~Process() {
    kill(os_pid, SIGKILL);
    int wstatus;
    waitpid(os_pid, &wstatus, 0);

    socket_listener.join();

    close(socket);

    {
        std::lock_guard<std::mutex> lg(awaiters_mu);
        for(auto& f : awaiters) f();
    }
}

void Process::add_awaiter(std::function<void()>&& awaiter) {
    std::lock_guard<std::mutex> lg(awaiters_mu);
    awaiters.push_back(std::move(awaiter));
}

void Process::serve_sandbox() {
    std::vector<uint8_t> m_buf(65536);
    struct iovec m_iov = { .iov_base = &m_buf[0], .iov_len = m_buf.size() };

    while(true) {
        struct msghdr msg = {
            .msg_iov = &m_iov,
            .msg_iovlen = 1,
        };
        ssize_t n_bytes = recvmsg(socket, &msg, 0);
        if(n_bytes <= 0) {
            break;
        }

        uint8_t *buf = &m_buf[0];
        size_t rem = n_bytes;

        if(rem < 4) continue;
        MessageType tag = (MessageType) (* (uint32_t *) buf);
        buf += 4; rem -= 4;

        switch(tag) {
            case MessageType::MODULE_REQUEST: {
                if(rem < 4) break;
                uint32_t full_name_len = * (uint32_t *) buf;
                buf += 4; rem -= 4;

                if(full_name_len == 0 || rem < full_name_len) break;
                std::string full_name((const char *) buf, full_name_len);
                auto maybe_name_info = parse_module_full_name(full_name.c_str());
                if(!maybe_name_info) {
                    std::cout << "Invalid module full name: " << full_name << std::endl;
                    send_reject(socket, "invalid module name");
                    break;
                }
                auto name_info = std::move(maybe_name_info.value());
                auto module_name = std::move(name_info.first);
                auto version_code = name_info.second;
                std::shared_ptr<DynamicModule> dm;
                try {
                    dm = DynamicModule::load_cached(module_name.c_str(), version_code);
                } catch(std::runtime_error& e) {
                    std::cout << "Error while trying to get module '" << module_name << "': " << e.what() << std::endl;
                    send_reject(socket, "missing/invalid module");
                    break;
                }

                std::vector<uint8_t> out(4 + dm->metadata.serialized.size());
                * (uint32_t *) &out[0] = (uint32_t) dm->metadata.serialized.size();
                std::copy(dm->metadata.serialized.begin(), dm->metadata.serialized.end(), &out[4]);

                Message msg;
                msg.ty = MessageType::MODULE_OFFER;
                msg.body = &out[0];
                msg.body_len = out.size();
                msg.fd = dm->mfd;

                if(msg.send(socket) < 0) {
                    std::cout << "Error while trying to send memfd to sandbox" << std::endl;
                    break;
                }
                break;
            }
            case MessageType::PROCESS_CREATE: {
                if(rem < sizeof(ProcessCreationInfo)) {
                    send_reject(socket);
                    break;
                }

                ProcessCreationInfo info;
                std::copy(buf, buf + sizeof(ProcessCreationInfo), (uint8_t *) &info);

                if(info.api_version != APIVER_ProcessCreationInfo) {
                    send_reject(socket, "api version mismatch");
                    break;
                }

                info.full_name[sizeof(info.full_name) - 1] = '\0';

                std::shared_ptr<Process> new_proc(new Process({ std::string(info.full_name) }));
                new_proc->parent_ck_pid = this->ck_pid;
                new_proc->privileged = this->privileged && info.privileged;

                global_process_set.attach_process(new_proc);
                auto new_pid = new_proc->ck_pid;
                new_proc->run();

                ProcessOfferMessage offer;
                offer.tag = (uint32_t) MessageType::PROCESS_OFFER;
                offer.offer.api_version = APIVER_ProcessOffer;
                offer.offer.pid = new_pid;
                send(socket, (void *) &offer, sizeof(offer), 0);
                break;
            }
            case MessageType::DEBUG_PRINT: {
                std::string message((const char *) buf, rem);
                std::cout << "[" << stringify_ck_pid(this->ck_pid) << "] " << message << std::endl;
                break;
            }
            case MessageType::PROCESS_WAIT: {
                if(rem < sizeof(ProcessWait)) {
                    send_reject(socket);
                    break;
                }

                ProcessWait info;
                std::copy(buf, buf + sizeof(ProcessWait), (uint8_t *) &info);

                auto remote_proc = global_process_set.get_process(info.pid);
                if(!remote_proc) {
                    send_reject(socket, "process not found");
                    break;
                }

                std::promise<void> ch;
                std::future<void> ch_fut;
                remote_proc->add_awaiter([&]() {
                    ch.set_value();
                });
                ch_fut.wait();
                send_ok(socket);
                break;
            }
            default: break; // invalid tag
        }
    }
}

ProcessSet::ProcessSet() : pid_rand_gen(pid_rand_dev()) {

}

ProcessSet::~ProcessSet() {

}

ck_pid_t ProcessSet::next_pid_locked() {
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t lower = dist(pid_rand_gen), upper = dist(pid_rand_gen);
    return (((__uint128_t) lower) | (((__uint128_t) upper) << 64));
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
    if(it != processes.end()) return it->second;
    else return std::shared_ptr<Process>();
}

void ProcessSet::notify_termination(ck_pid_t pid) {
    std::lock_guard<std::mutex> lg(this->mu);
    pending_termination.push_back(pid);
}

void ProcessSet::tick() {
    std::lock_guard<std::mutex> lg(this->mu);

    for(auto pid : pending_termination) {
        auto it = processes.find(pid);
        if(it != processes.end()) processes.erase(it);
    }
    pending_termination.clear();
}

ProcessSet global_process_set;
