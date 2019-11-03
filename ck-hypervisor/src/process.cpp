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
    TrivialResult result(0, "");
    return result.kernel_message().send(socket);
}

static int send_ok(int socket, const char *description) {
    TrivialResult result(0, description);
    return result.kernel_message().send(socket);
}

static int send_reject(int socket) {
    TrivialResult result(-1, "");
    return result.kernel_message().send(socket);
}

static int send_reject(int socket, const char *reason) {
    TrivialResult result(-1, reason);
    return result.kernel_message().send(socket);
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
        ss << "CK_HYPERVISOR_FD=" << sockets[1];
        auto socket_id_env_str = ss.str();

        int flags = fcntl(sockets[1], F_GETFD, 0);
        flags &= ~FD_CLOEXEC;
        if(fcntl(sockets[1], F_SETFD, flags) < 0) {
            std::cout << "unable to clear cloexec" << std::endl;
            exit(1);
        }

        std::vector<char *> args_exec;
        args_exec.push_back((char *) "ck-hypervisor-sandbox");
        for(auto& arg : args) {
            args_exec.push_back((char *) arg.c_str());
        }
        args_exec.push_back(nullptr);

        std::vector<char *> envp_exec;
        if(privileged) envp_exec.push_back((char *) "CK_PRIVILEGED=1");
        else envp_exec.push_back((char *) "CK_PRIVILEGED=0");
        envp_exec.push_back((char *) socket_id_env_str.c_str());
        envp_exec.push_back(nullptr);

        if(setgid(65534) != 0 || setuid(65534) != 0) {
            std::cout << "unable to drop permissions" << std::endl;
            if(getuid() == 0) {
                std::cout << "cannot continue as root." << std::endl;
                exit(1);
            }
        }
        execve("./ck-hypervisor-sandbox", &args_exec[0], &envp_exec[0]);
        exit(1);
    } else {
        close(sockets[1]);
        socket = sockets[0];
        os_pid = new_pid;

        socket_listener = std::thread([this]() {
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);
            serve_sandbox();
            global_process_set.notify_termination(this->ck_pid);
        });
    }
}

Process::~Process() {
    kill(os_pid, SIGKILL);
    int wstatus;
    waitpid(os_pid, &wstatus, 0);

    pthread_cancel(socket_listener.native_handle());
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

void Process::handle_kernel_message(uint64_t session, MessageType tag, uint8_t *data, size_t rem) {
    if(session != 0) {
        send_reject(socket, "invalid kernel session");
        return;
    }
    switch(tag) {
        case MessageType::MODULE_REQUEST: {
            std::string full_name((const char *) data, rem);
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

            Message msg;
            msg.tag = MessageType::MODULE_OFFER;
            msg.body = dm->metadata.serialized.empty() ? nullptr : &dm->metadata.serialized[0];
            msg.body_len = dm->metadata.serialized.size();
            msg.fd = dm->mfd;

            msg.send(socket);
            break;
        }
        case MessageType::PROCESS_CREATE: {
            if(rem < sizeof(ProcessCreationInfo)) {
                send_reject(socket);
                break;
            }

            ProcessCreationInfo info;
            std::copy(data, data + sizeof(ProcessCreationInfo), (uint8_t *) &info);

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

            ProcessOffer offer;
            offer.api_version = APIVER_ProcessOffer;
            offer.pid = new_pid;
            
            Message offer_msg;
            offer_msg.tag = MessageType::PROCESS_OFFER;
            offer_msg.body = (const uint8_t *) &offer;
            offer_msg.body_len = sizeof(offer);

            send_ok(socket);
            offer_msg.send(socket);

            break;
        }
        case MessageType::DEBUG_PRINT: {
            std::string message((const char *) data, rem);
            std::cout << "[" << stringify_ck_pid(this->ck_pid) << "] " << message << std::endl;
            send_ok(socket);
            break;
        }
        case MessageType::PROCESS_WAIT: {
            if(rem < sizeof(ProcessWait)) {
                send_reject(socket);
                break;
            }

            ProcessWait info;
            std::copy(data, data + sizeof(ProcessWait), (uint8_t *) &info);

            auto remote_proc = global_process_set.get_process(info.pid);
            if(!remote_proc) {
                send_reject(socket, "process not found");
                break;
            }

            std::promise<void> ch;
            std::future<void> ch_fut = ch.get_future();
            remote_proc->add_awaiter([&]() {
                ch.set_value();
            });
            {
                auto _x = std::move(remote_proc); // drop
            }
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
            ch_fut.wait();
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);
            send_ok(socket);
            break;
        }
        case MessageType::POLL: {
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
            auto msg = pending_messages.pop();
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);

            auto out = msg.borrow();
            out.send(socket);
            break;
        }
        case MessageType::SERVICE_REGISTER: {
            if(!privileged) {
                send_reject(socket, "permission denied");
                break;
            }

            if(rem > MAX_SERVICE_NAME_SIZE) {
                send_reject(socket, "name too long");
                break;
            }

            std::string name((const char *) data, rem);
            bool registered = global_process_set.register_service(std::move(name), this->ck_pid);

            if(registered) {
                send_ok(socket);
            } else {
                send_reject(socket, "duplicate name");
            }
            break;
        }
        case MessageType::SERVICE_GET: {
            std::string name((const char *) data, rem);
            if(auto pid = global_process_set.get_service(name.c_str())) {
                std::string pid_s = stringify_ck_pid(pid.value());
                send_ok(socket, pid_s.c_str());
            } else {
                send_reject(socket, "service not found");
            }
            break;
        }
        default: break; // invalid tag
    }
}

void Process::serve_sandbox() {
    ck_pid_t recipient;
    uint64_t session;
    uint32_t raw_tag;
    std::vector<uint8_t> m_buf(MAX_MESSAGE_BODY_SIZE);

    struct iovec parts[4];
    parts[0].iov_base = (void *) &recipient;
    parts[0].iov_len = sizeof(ck_pid_t);
    parts[1].iov_base = (void *) &session;
    parts[1].iov_len = sizeof(uint64_t);
    parts[2].iov_base = (void *) &raw_tag;
    parts[2].iov_len = sizeof(uint32_t);
    parts[3].iov_base = &m_buf[0];
    parts[3].iov_len = m_buf.size();

    const int header_size = sizeof(ck_pid_t) + sizeof(uint64_t) + sizeof(uint32_t);

    while(true) {
        struct msghdr msg = {
            .msg_iov = parts,
            .msg_iovlen = 4,
        };
        ssize_t size = recvmsg(socket, &msg, 0);
        if(size < header_size) {
            break;
        }
        size -= header_size;

        MessageType tag = (MessageType) raw_tag;
        if(recipient == 0) {
            handle_kernel_message(session, tag, &m_buf[0], size);
        } else {
            auto remote_proc = global_process_set.get_process(recipient);
            if(!remote_proc) send_reject(socket, "recipient not found");
            else {
                OwnedMessage owned;
                owned.sender_or_recipient = this->ck_pid; // sender
                owned.session = session;
                owned.tag = tag;
                owned.body = std::vector<uint8_t>(&m_buf[0], &m_buf[size]);
                remote_proc->pending_messages.push(std::move(owned));
                send_ok(socket);
            }
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

bool ProcessSet::register_service(std::string&& name, ck_pid_t pid) {
    std::lock_guard<std::mutex> lg(this->mu);
    auto [it, inserted] = services.insert({std::move(name), pid});
    return inserted;
}

std::optional<ck_pid_t> ProcessSet::get_service(const char *name) {
    std::lock_guard<std::mutex> lg(this->mu);
    auto it = services.find(name);
    if(it != services.end()) {
        return it->second;
    } else {
        return std::nullopt;
    }
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
