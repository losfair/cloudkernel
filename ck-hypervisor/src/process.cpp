#include <ck-hypervisor/process.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sstream>
#include <string>
#include <iostream>
#include <thread>
#include <signal.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/registry.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/config.h>
#include <regex>
#include <pthread.h>

static int send_reject(int socket) {
    uint32_t buf = (uint32_t) MessageType::MODULE_REJECT;
    return send(socket, (void *) &buf, sizeof(buf), 0);
}

Process::Process(const std::vector<std::string>& args) {
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
        pid = new_pid;

        socket_listener = std::thread([this]() {
            serve_sandbox();
        });
    }
}

Process::~Process() {
    if(!no_kill_at_destruction) {
        kill(pid, SIGKILL);
        int wstatus;
        waitpid(pid, &wstatus, 0);
    }

    socket_listener.join();

    close(socket);
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
        std::lock_guard<std::mutex> lg(this->mu);

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
                std::string full_name(full_name_len, '\0');
                std::copy((char *) buf, (char *) buf + full_name_len, &full_name[0]);
                std::regex re("(.+)_([0-9]+).([0-9]+).([0-9]+)");
                std::cmatch cm;
                if(!std::regex_match(full_name.c_str(), cm, re)) {
                    std::cout << "Regex match failed." << std::endl;
                    std::move(lg);
                    send_reject(socket);
                } else {
                    if(cm.size() != 5) {
                        std::cout << "invalid CM size: "  << cm.size() << std::endl;
                        std::move(lg);
                        send_reject(socket);
                        break;
                    }
                    std::string module_name(cm[1].str());
                    VersionCode version_code;
                    std::stringstream ss;
                    ss << cm[2] << ' ' << cm[3] << ' ' << cm[4];
                    ss >> version_code.major >> version_code.minor >> version_code.patch;
                    std::shared_ptr<DynamicModule> dm;
                    try {
                        dm = DynamicModule::load_cached(module_name.c_str(), version_code);
                    } catch(std::runtime_error& e) {
                        std::cout << "Error while trying to get module '" << module_name << "': " << e.what() << std::endl;
                        std::move(lg);
                        send_reject(socket);
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

                    std::move(lg);
                    if(msg.send(socket) < 0) {
                        std::cout << "Error while trying to send memfd to sandbox" << std::endl;
                        break;
                    }
                }
                break;
            }
            default: break; // invalid tag
        }
    }
}