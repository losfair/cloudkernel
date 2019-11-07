#include <ck-hypervisor/process.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
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
#include <ck-hypervisor/syscall.h>
#include <regex>
#include <pthread.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

static const bool permissive_mode = false;

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

void Process::run_as_child(int socket) {
    std::stringstream ss;
    ss << "CK_HYPERVISOR_FD=" << socket;
    auto socket_id_env_str = ss.str();

    int flags = fcntl(socket, F_GETFD, 0);
    flags &= ~FD_CLOEXEC;
    if(fcntl(socket, F_SETFD, flags) < 0) {
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
}

Process::Process(const std::vector<std::string>& new_args) {
    args = new_args;
    io_map.setup_defaults();
}

bool Process::read_memory(unsigned long remote_addr, size_t len, uint8_t *data) {
    if(len == 0) return true;

    iovec local_iov = {
        .iov_base = (void*) data,
        .iov_len = len,
    };
    iovec remote_iov = {
        .iov_base = (void *) remote_addr,
        .iov_len = len,
    };
    if(process_vm_readv(os_pid, &local_iov, 1, &remote_iov, 1, 0) != len) return false;
    else return true;
}

bool Process::write_memory(unsigned long remote_addr, size_t len, const uint8_t *data) {
    if(len == 0) return true;

    iovec local_iov = {
        .iov_base = (void*) data,
        .iov_len = len,
    };
    iovec remote_iov = {
        .iov_base = (void *) remote_addr,
        .iov_len = len,
    };
    if(process_vm_writev(os_pid, &local_iov, 1, &remote_iov, 1, 0) != len) return false;
    else return true;
}

std::optional<std::string> Process::read_c_string(unsigned long remote_addr, size_t max_size) {
    std::string s;
    while(true) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, os_pid, (void *) remote_addr, nullptr);
        if(errno) return std::nullopt;
        uint8_t *bytes = (uint8_t *) &word;
        for(int i = 0; i < sizeof(word); i++) {
            if(bytes[i] == 0) return s;
            if(s.size() == max_size) return std::nullopt;
            s.push_back(bytes[i]);
        }
        remote_addr += sizeof(word);
    }
}

void Process::run() {
    int sockets[2];

    if(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0) {
        throw std::runtime_error("unable to create socket pair");
    }

    std::promise<void> child_pid;
    std::future<void> child_pid_fut = child_pid.get_future();
    ptrace_monitor = std::thread([this, &child_pid, sockets]() {
        int new_pid = fork();
        if(new_pid < 0) throw std::runtime_error("unable to create process");
        if(new_pid == 0) {
            close(sockets[0]);
            run_as_child(sockets[1]);
            _exit(1);
        }
        os_pid = new_pid;
        child_pid.set_value();

        try {
            run_ptrace_monitor();
        } catch(const std::runtime_error& e) {
            std::cout << "ptrace monitor exited with error: " << e.what() << std::endl;
        }
        global_process_set.notify_termination(this->ck_pid);
    });

    child_pid_fut.wait();
    close(sockets[1]);
    socket = sockets[0];

    socket_listener = std::thread([this]() {
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, nullptr);
        serve_sandbox();
        global_process_set.notify_termination(this->ck_pid);
    });
}

Process::~Process() {
    kill_requested.store(true);
    kill(os_pid, SIGTERM);
    ptrace_monitor.join(); // ptrace_monitor will handle the waitpid() cleanup stuff.

    pthread_cancel(socket_listener.native_handle());
    socket_listener.join();

    close(socket);

    {
        std::lock_guard<std::mutex> lg(awaiters_mu);
        for(auto& f : awaiters) f();
    }
}

void Process::run_ptrace_monitor() {
    int wstatus;
    assert(waitpid(os_pid, &wstatus, 0) >= 0);

    if(WSTOPSIG(wstatus) != SIGSTOP) {
        throw std::runtime_error("Expecting a SIGSTOP but got something else.");
    }

    if(ptrace(PTRACE_SETOPTIONS, os_pid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0) {
        throw std::runtime_error("Unable to call ptrace() on sandbox process.");
    }

    std::cout << "Monitor initialized on process " << os_pid << "/" << stringify_ck_pid(ck_pid) << std::endl;

    int stopsig = 0;

    while(true) {
        ptrace(PTRACE_SYSCALL, os_pid, 0, stopsig);
        assert(waitpid(os_pid, &wstatus, 0) >= 0);

        // Normal exit or killed.
        if(WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            break;
        }

        stopsig = WSTOPSIG(wstatus);

        user_regs_struct regs = {};
        ptrace(PTRACE_GETREGS, os_pid, 0, &regs);

        TraceContinuationState tcs = TraceContinuationState::CLEANUP;
        if(stopsig == (SIGTRAP | 0x80)) { // system call
            tcs = handle_syscall(regs, stopsig);
            if(tcs == TraceContinuationState::CONTINUE && stopsig != (SIGTRAP | 0x80)) {
                tcs = handle_signal(regs, stopsig);
            } else {
                stopsig = 0;
            }
        } else {
            tcs = handle_signal(regs, stopsig);
        }

        switch(tcs) {
            case TraceContinuationState::CONTINUE:
                break;
            case TraceContinuationState::CLEANUP:
                kill(os_pid, SIGKILL);
                assert(waitpid(os_pid, &wstatus, 0) >= 0);
                if(!WIFSIGNALED(wstatus)) {
                    throw std::runtime_error("Got unexpected status after sending SIGKILL.");
                }
                goto out;
            case TraceContinuationState::BREAK:
                goto out;
            default: assert(false);
        }
    }

    out:

    std::cout << "Monitor exited on process " << os_pid << "/" << stringify_ck_pid(ck_pid) << std::endl;
}

enum class SyscallFixupMethod {
    SET_VALUE,
    SEND_SIGSYS,
};

bool Process::register_returned_fd_after_syscall(user_regs_struct& regs, const std::filesystem::path& parent_path, const std::string& path) {
    if(regs.rax >= 0) {
        auto desc = std::shared_ptr<FileDescription>(new FileDescription);
        desc->os_fd = regs.rax;
        desc->path = parent_path;
        desc->path += path;
        desc->ty = FileInstanceType::NORMAL;
        int vfd = io_map.insert_file_description(std::move(desc));
        regs.rax = vfd;
        ptrace(PTRACE_SETREGS, os_pid, 0, &regs);
    }

    return false; // is_invalid = false
}

TraceContinuationState Process::handle_syscall(user_regs_struct regs, int& stopsig_out) {
    bool is_invalid = false;
    SyscallFixupMethod fixup_method = SyscallFixupMethod::SET_VALUE;
    long replace_value = -EPERM;

    long nr = regs.orig_rax;
    std::vector<DeferredSyscallHandler> deferred;

    if(sandbox_state.load() == SandboxState::NONE) switch(nr) {
        case __NR_execve: {
            std::cout << "Entering sandbox: " << os_pid << "/" << stringify_ck_pid(ck_pid) << std::endl;
            sandbox_state.store(SandboxState::IN_EXEC);
            break;
        }
        case CK_SYS_SET_REMOTE_HYPERVISOR_FD: {
            int remote_fd = regs.rdi;
            int vfd = io_map.insert_file_description(FileDescription::with_hypervisor_fd(remote_fd));
            std::cout << "Remote hypervisor fd: " << remote_fd << "->" << vfd << std::endl;
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = 0;
            break;
        }
        default: break;
    } else switch(nr) {
        // process
        case __NR_exit_group:
            break;

        // IO
        case __NR_lseek:
        case __NR_write:
        case __NR_read:
        case __NR_sendto:
        case __NR_recvfrom:
        case __NR_sendmsg:
        case __NR_recvmsg:
        case __NR_fstat:
        {
            int orig_fd = regs.rdi;
            if(auto desc = io_map.get_file_description(orig_fd)) {
                regs.rdi = desc->os_fd;
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EBADF;
            }
            break;
        }
        case __NR_close:
        {
            int orig_fd = regs.rdi;
            if(auto desc = io_map.get_file_description(orig_fd)) {
                regs.rdi = desc->os_fd;
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EBADF;
            }
            deferred.push_back([this, orig_fd](user_regs_struct& regs) -> bool {
                if(regs.rax == 0) {
                    io_map.remove_file_description(orig_fd);
                }
                return false;
            });
            break;
        }

        // memory
        case __NR_brk:
        case __NR_mmap:
        case __NR_munmap:

        // signal handling
        case __NR_rt_sigprocmask:
        case __NR_rt_sigreturn:
        case __NR_rt_sigaction:
        case __NR_sigaltstack:

        // sleep
        case __NR_nanosleep:
        case __NR_clock_nanosleep:

        // system information
        case __NR_uname:
            break;

        case __NR_readlink:
            break;

        case __NR_openat: {
            auto dirfd = io_map.get_file_description(regs.rdi);
            if(!dirfd) {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EBADF;
                break;
            }
            if(auto maybe_path = read_c_string(regs.rsi, 65536)) {
                std::string path = std::move(maybe_path.value());
                deferred.push_back([this, dirfd(std::move(dirfd)), path(std::move(path))](user_regs_struct& regs) {
                    return register_returned_fd_after_syscall(regs, dirfd->path, path);
                });
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EFAULT;
            }
            break;
        }
        case __NR_open: {
            if(auto maybe_path = read_c_string(regs.rdi, 65536)) {
                std::string path = std::move(maybe_path.value());
                deferred.push_back([this, path(std::move(path))](user_regs_struct& regs) {
                    return register_returned_fd_after_syscall(regs, {}, path);
                });
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EFAULT;
            }
            break;
        }

        case __NR_arch_prctl: {
            long code = regs.rdi;
            if(code == ARCH_SET_FS || code == ARCH_GET_FS || code == ARCH_SET_GS || code == ARCH_GET_GS) {
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SEND_SIGSYS;
            }
            break;
        }
        case __NR_set_tid_address: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = 0;
            break;
        }
        case CK_SYS_GET_ABI_VERSION: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = CK_ABI_VERSION;
            break;
        }
        case CK_SYS_NOTIFY_INVALID_SYSCALL: {
            notify_invalid_syscall.store(true);
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = 0;
            break;
        }
        default:
            if(permissive_mode) {
                std::cout << "Warning (permissive mode): Process " << os_pid << "/" << stringify_ck_pid(ck_pid) << " invoked an unknown syscall: " << nr << std::endl;
            } else {
                is_invalid = true;
                if(notify_invalid_syscall.load()) {
                    fixup_method = SyscallFixupMethod::SEND_SIGSYS;
                } else {
                    std::cout << "Invalid syscall: " << nr << std::endl;
                    fixup_method = SyscallFixupMethod::SET_VALUE;
                    replace_value = -EPERM;
                }
            }
            break;
    }

    if(is_invalid) {
        regs.orig_rax = __NR_getpid;
        ptrace(PTRACE_SETREGS, os_pid, 0, &regs);
    }

    ptrace(PTRACE_SYSCALL, os_pid, 0, 0);
    int wstatus = 0;
    assert(waitpid(os_pid, &wstatus, 0) >= 0);

    int stopsig = WSTOPSIG(wstatus);
    if(WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
        return TraceContinuationState::BREAK;
    }

    stopsig = WSTOPSIG(wstatus);
    if(stopsig == (SIGTRAP | 0x80)) {
        ptrace(PTRACE_GETREGS, os_pid, 0, &regs);
        if(!is_invalid) for(auto it = deferred.rbegin(); it != deferred.rend(); it++) {
            is_invalid = (*it)(regs);
            if(is_invalid) {
                fixup_method = SyscallFixupMethod::SEND_SIGSYS;
                break;
            }
        }
        if(is_invalid) {
            switch(fixup_method) {
                case SyscallFixupMethod::SET_VALUE: {
                    regs.rax = replace_value;
                    ptrace(PTRACE_SETREGS, os_pid, 0, &regs);
                    break;
                }
                case SyscallFixupMethod::SEND_SIGSYS: {
                    regs.rax = nr;
                    ptrace(PTRACE_SETREGS, os_pid, 0, &regs);
                    kill(os_pid, SIGSYS);
                    break;
                }
                default: assert(false);
            }
        }
    } else {
        stopsig_out = stopsig;
    }

    return TraceContinuationState::CONTINUE;
}

TraceContinuationState Process::handle_signal(user_regs_struct regs, int& sig) {
    if(sig == SIGTERM && kill_requested.load()) {
        return TraceContinuationState::CLEANUP;
    }
    if(sig == SIGTRAP && this->sandbox_state.load() == SandboxState::IN_EXEC) {
        sig = 0;
        this->sandbox_state.store(SandboxState::IN_SANDBOX);
    }
    return TraceContinuationState::CONTINUE;
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
            msg.body = nullptr;
            msg.body_len = 0;
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
    pending_termination.insert(pid);
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
