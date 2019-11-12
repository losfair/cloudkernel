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
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/registry.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/config.h>
#include <ck-hypervisor/process_api.h>
#include <ck-hypervisor/syscall.h>
#include <regex>
#include <chrono>
#include <pthread.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <ck-hypervisor/network.h>
#include <sys/personality.h>

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
    personality(ADDR_NO_RANDOMIZE); // snapshoting requires deterministic address space layout
    if(socket != 3) {
        if(dup2(socket, 3) < 0) {
            printf("cannot duplicate socket fd\n");
            exit(1);
        }
        close(socket);
        socket = 3;
    }

    int flags = fcntl(socket, F_GETFD, 0);
    flags &= ~FD_CLOEXEC;
    if(fcntl(socket, F_SETFD, flags) < 0) {
        printf("unable to clear cloexec flag\n");
        exit(1);
    }

    std::vector<char *> args_exec;
    args_exec.push_back((char *) "ck-hypervisor-sandbox");
    for(auto& arg : args) {
        args_exec.push_back((char *) arg.c_str());
    }
    args_exec.push_back(nullptr);

    if(setgid(65534) != 0 || setuid(65534) != 0) {
        printf("unable to drop permissions\n");
        if(getuid() == 0) {
            printf("cannot continue as root.\n");
            exit(1);
        }
    }
    execv("./ck-hypervisor-sandbox", &args_exec[0]);
}

Process::Process(const std::vector<std::string>& new_args) {
    args = new_args;
    io_map.setup_defaults();
    pending_messages.set_capacity(1024);
}

static bool read_process_memory(int os_pid, unsigned long remote_addr, size_t len, uint8_t *data) {
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

static bool write_process_memory(int os_pid, unsigned long remote_addr, size_t len, const uint8_t *data) {
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

static void print_regs(const user_regs_struct& regs) {
    printf("rax: %p\n", (void *) regs.rax);
    printf("rbx: %p\n", (void *) regs.rbx);
    printf("rcx: %p\n", (void *) regs.rcx);
    printf("rdx: %p\n", (void *) regs.rdx);
    printf("rdi: %p\n", (void *) regs.rdi);
    printf("rsi: %p\n", (void *) regs.rsi);
    printf("rsp: %p\n", (void *) regs.rsp);
    printf("rbp: %p\n", (void *) regs.rbp);
    printf("r8: %p\n", (void *) regs.r8);
    printf("r9: %p\n", (void *) regs.r9);
    printf("r10: %p\n", (void *) regs.r10);
    printf("r11: %p\n", (void *) regs.r11);
    printf("r12: %p\n", (void *) regs.r12);
    printf("r13: %p\n", (void *) regs.r13);
    printf("r14: %p\n", (void *) regs.r14);
    printf("r15: %p\n", (void *) regs.r15);
    printf("rip: %p\n", (void *) regs.rip);
}

bool Process::read_memory(unsigned long remote_addr, size_t len, uint8_t *data) {
    return read_process_memory(os_pid, remote_addr, len, data);
}

bool Process::write_memory(unsigned long remote_addr, size_t len, const uint8_t *data) {
    return write_process_memory(os_pid, remote_addr, len, data);
}

void Process::run() {
    int sockets[2];

    if(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) < 0) {
        throw std::runtime_error("unable to create socket pair");
    }

    std::promise<void> child_pid;
    std::future<void> child_pid_fut = child_pid.get_future();

    std::thread([this, &child_pid, sockets]() {
        int new_pid = fork();
        if(new_pid < 0) throw std::runtime_error("unable to create process");
        if(new_pid == 0) {
            close(sockets[0]);
            run_as_child(sockets[1]);
            _exit(1);
        }
        os_pid = new_pid;

        auto th = Thread::first_thread(this); // reads `os_pid`
        Thread *th_ref = &*th;
        {
            std::lock_guard<std::mutex> lg(threads_mu);
            threads[th->os_tid] = std::move(th);
        }

        // The new thread must have been inserted to `this->threads` before we can allow `Process::run` to return,
        // to ensure that the `Process` object has a strictly longer lifetime than any thread it contains.
        // Otherwise the `Process` destructor might not observe the newly created thread, and `Thread` will try to
        // use a dangling pointer to access the process it belongs to.
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
    while(true) {
        {
            std::lock_guard<std::mutex> lg(threads_mu);
            if(threads.empty()) break;
        }
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10ms);
    }

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

static std::optional<std::vector<MemoryRangeSnapshot>> take_memory_snapshot(int os_pid) {
    std::stringstream name_ss;
    name_ss << "/proc/" << os_pid << "/maps";
    std::string name = name_ss.str();

    std::ifstream maps(name.c_str());
    if(!maps) {
        return std::nullopt;
    }

    std::regex re("([0-9a-f]+)-([0-9a-f]+) (....) ([0-9a-f]+) (..):(..) ([0-9]+)( *)(.*)");
    std::vector<MemoryRangeSnapshot> result;

    while(!maps.eof()) {
        std::string line;
        std::getline(maps, line);
        
        std::cmatch cm;
        if(!std::regex_match(line.c_str(), cm, re)) {
            break;
        } else {
            if(cm.size() != 10) {
                printf("take_memory_snapshot: unexpected match size\n");
                return std::nullopt;
            }

            uint64_t start = 0, end = 0;
            std::string perms = cm[3].str(), path = cm[9].str();

            {
                std::stringstream ss;
                ss << std::hex << cm[1];
                ss >> start;
            }
            {
                std::stringstream ss;
                ss << std::hex << cm[2];
                ss >> end;
            }

            if(end <= start) {
                printf("take_memory_snapshot: end <= start\n");
                return std::nullopt;
            }

            MemoryRangeSnapshot mss;
            mss.start = start;
            if(perms.size() != 4) {
                printf("take_memory_snapshot: unexpected 'perms' length\n");
                return std::nullopt;
            }
            if(perms[0] == 'r') mss.prot |= PROT_READ;
            if(perms[1] == 'w') mss.prot |= PROT_WRITE;
            if(perms[2] == 'x') mss.prot |= PROT_EXEC;

            if(path == "[vvar]" || path == "[vdso]" || path == "[vsyscall]") {
                continue; // do not dump these regions
            }

            if(path == "[heap]") {
                mss.ty = MemoryRangeType::HEAP;
            } else if(path == "[stack]") {
                mss.ty = MemoryRangeType::STACK;
            } else {
                mss.ty = MemoryRangeType::DATA;
            }

            mss.data_feed = [os_pid, start, end](uint8_t *out) {
                if(!read_process_memory(os_pid, start, end - start, out)) {
                    printf("take_memory_snapshot: unable to read process memory from %lx to %lx\n", start, end);
                    throw std::runtime_error("take_memory_snapshot: unable to read process memory");
                }
            };
            mss.data_len = end - start;

            result.push_back(std::move(mss));
        }
    }

    return result;
}

std::shared_ptr<std::vector<uint8_t>> Process::take_snapshot() {
    ProcessSnapshot snapshot;

    snapshot.notify_invalid_syscall = this->notify_invalid_syscall.load();
    ptrace(PTRACE_GETREGS, os_pid, 0, &snapshot.regs);

    if(auto ss = take_memory_snapshot(os_pid)) {
        snapshot.memory = std::move(ss.value());
    } else {
        return {};
    }

    snapshot.files = io_map.snapshot_files();

    try {
        return std::shared_ptr<std::vector<uint8_t>>(new std::vector<uint8_t>(snapshot.serialize()));
    } catch(std::runtime_error& e) {
        return {};
    }
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
                printf("handle_kernel_message: MODULE_REQUEST: Invalid module full name: %s\n", full_name.c_str());
                send_reject(socket, "invalid module name");
                break;
            }
            auto name_info = std::move(maybe_name_info.value());
            auto module_name = std::move(name_info.first);
            auto version_code = name_info.second;
            std::string module_type = "";

            std::shared_ptr<DynamicModule> dm;
            try {
                static const std::string snapshot_prefix = "snapshot:";
                if(auto [left, right] = std::mismatch(module_name.begin(), module_name.end(), snapshot_prefix.begin(), snapshot_prefix.end()); right == snapshot_prefix.end()) {
                    std::string snapshot_pid;
                    std::copy(left, module_name.end(), std::back_inserter(snapshot_pid));
                    if(snapshot_pid.size() != 32) {
                        throw std::runtime_error("bad snapshot pid size");
                    }
                    __uint128_t target = 0;
                    {
                        uint64_t *target_b = (uint64_t *) &target;
                        if(sscanf(snapshot_pid.c_str(), "%016lx%016lx", &target_b[1], &target_b[0]) != 2) {
                            throw std::runtime_error("invalid snapshot pid");
                        }
                    }
                    auto remote_proc = global_process_set.get_process(target);
                    if(!remote_proc) {
                        throw std::runtime_error("remote process not found");
                    }
                    auto ss = remote_proc->get_last_snapshot();
                    if(!ss) {
                        throw std::runtime_error("no snapshot for the provided remote process");
                    }
                    dm = DynamicModule::load_cached(module_name.c_str(), VersionCode(), [&]() { return new DynamicModule([&](uint8_t *out) {
                        std::copy(&(*ss)[0], &(*ss)[ss->size()], out);
                    }, ss->size()); });
                    module_type = "snapshot";
                } else {
                    dm = DynamicModule::load_cached(module_name.c_str(), version_code, [&]() {
                        return new DynamicModule(module_name.c_str(), version_code);
                    });
                    module_type = "elf";
                }
                
            } catch(std::runtime_error& e) {
                printf("Error while trying to get module '%s': %s\n", module_name.c_str(), e.what());
                send_reject(socket, "missing/invalid module");
                break;
            }

            // We cannot pass the memfd back directly because we want syscalls like `lseek`
            // to be independent.
            std::stringstream fd_handle_path_ss;
            fd_handle_path_ss << "/proc/" << getpid() << "/fd/" << dm->mfd;
            std::string fd_handle_path = fd_handle_path_ss.str();
            int fd_handle = open(fd_handle_path.c_str(), O_RDONLY);
            if(fd_handle < 0) {
                send_reject(socket, "cannot open mfd");
                break;
            }

            Message msg;
            msg.tag = MessageType::MODULE_OFFER;
            msg.body = (const uint8_t *) &module_type[0];
            msg.body_len = module_type.size();
            msg.fd = fd_handle;

            msg.send(socket);
            close(fd_handle);
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
            auto ck_pid_s = stringify_ck_pid(this->ck_pid);
            printf("[%s] %s\n", ck_pid_s.c_str(), message.c_str());
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
            ch_fut.wait();
            send_ok(socket);
            break;
        }
        case MessageType::POLL: {
            if(auto maybe_msg = pending_messages.pop()) {
                auto msg = std::move(maybe_msg.value());
                auto out = msg.borrow();
                out.send(socket);
            }
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
        case MessageType::IP_PACKET: {
            if(rem == 0 || rem > 1500) break;
            global_router.dispatch_packet(data, rem);
            break;
        }
        case MessageType::IP_ADDRESS_REGISTER_V4: {
            if(rem != 4) {
                send_reject(socket, "invalid address length");
                break;
            }

            uint32_t addr = * (uint32_t *) data;
            std::reverse((uint8_t *) &addr, ((uint8_t *) &addr) + 4);
            __uint128_t full_addr = ((__uint128_t) 0xffff00000000ull) | (__uint128_t) addr;

            auto endpoint = std::shared_ptr<RoutingEndpoint>(new RoutingEndpoint);

            // This function can be recursively called within another `handle_kernel_message`.
            // Make sure locks are held properly.
            endpoint->on_packet = [full_addr, ck_pid(this->ck_pid)](uint8_t *data, size_t len) {
                if(auto proc = global_process_set.get_process(ck_pid)) {
                    OwnedMessage msg;
                    msg.tag = MessageType::IP_PACKET;
                    msg.body = std::vector<uint8_t>(data, data + len);
                    proc->pending_messages.push(std::move(msg));
                } else {
                    global_router.unregister_route(full_addr, ck_pid);
                }
            };
            global_router.register_route(full_addr, std::move(endpoint));

            send_ok(socket);
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

Thread::~Thread() {

}

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

std::optional<std::string> Thread::read_c_string(unsigned long remote_addr, size_t max_size) {
    std::string s;
    while(true) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, os_tid, (void *) remote_addr, nullptr);
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

void Thread::run() {
    try {
        run_ptrace_monitor();
    } catch(const std::runtime_error& e) {
        printf("ptrace monitor exited with error: %s\n", e.what());
    }
    {
        std::lock_guard<std::mutex> lg(process->threads_mu);
        if(auto it = process->threads.find(os_tid); it != process->threads.end()) {
            // This is the ONLY place where `process->threads.erase` is allowed to happen.
            process->threads.erase(it);
        } else {
            throw std::logic_error("Thread id not found in process->threads");
        }
    }
    if(os_tid == this->process->os_pid) {
        global_process_set.notify_termination(this->process->ck_pid);
    }
}

void Thread::run_ptrace_monitor() {
    int wstatus;
    if(waitpid(os_tid, &wstatus, 0) < 0) return;

    if(WSTOPSIG(wstatus) != SIGSTOP) {
        return;
    }

    if(ptrace(PTRACE_SETOPTIONS, os_tid, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE) < 0) {
        printf("Unable to call ptrace() on sandbox thread.\n");
        return;
    }

    /*{
        auto ck_pid_s = stringify_ck_pid(process->ck_pid);
        printf("Monitor initialized on thread %d/%s\n", os_tid, ck_pid_s.c_str());
    }*/

    int stopsig = 0;

    while(true) {
        ptrace(PTRACE_SYSCALL, os_tid, 0, stopsig);
        if(waitpid(os_tid, &wstatus, 0) < 0) break;

        // Normal exit or killed.
        if(WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
            break;
        }

        stopsig = WSTOPSIG(wstatus);

        user_regs_struct regs = {};
        ptrace(PTRACE_GETREGS, os_tid, 0, &regs);

        TraceContinuationState tcs = TraceContinuationState::BREAK;
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
            case TraceContinuationState::BREAK:
                goto out;
            default: assert(false);
        }
    }

    out:;

    /*{
        auto ck_pid_s = stringify_ck_pid(process->ck_pid);
        printf("Monitor exited on thread %d/%s\n", os_tid, ck_pid_s.c_str());
    }*/
}

bool Thread::register_returned_fd_after_syscall(user_regs_struct& regs, const std::filesystem::path& parent_path, const std::string& path, int flags) {
    if(regs.rax >= 0) {
        auto full_path = parent_path;
        full_path += path;
        process->insert_fd(regs.rax, false, full_path, flags);
    }

    return false; // is_invalid = false
}

TraceContinuationState Thread::handle_syscall(user_regs_struct regs, int& stopsig_out) {
    bool is_invalid = false;
    SyscallFixupMethod fixup_method = SyscallFixupMethod::SET_VALUE;
    long replace_value = -EPERM;

    long nr = regs.orig_rax;
    std::vector<DeferredSyscallHandler> deferred;

    if(process->sandbox_state.load() == SandboxState::NONE) switch(nr) {
        case __NR_execve: {
            process->sandbox_state.store(SandboxState::IN_EXEC);
            break;
        }
        case CK_SYS_ENTER_SANDBOX: {
            process->sandbox_state.store(SandboxState::IN_SANDBOX);
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = 0;
            break;
        }
        default: break;
    } else switch(nr) {
        // memory
        case __NR_brk:
        case __NR_mmap:
        case __NR_munmap:
        case __NR_mprotect:
        case __NR_madvise:

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

        // sync
        case __NR_futex:

        // process
        case __NR_prctl:
        case __NR_arch_prctl:
        case __NR_set_tid_address:
        case __NR_exit_group:
        case __NR_exit:
        case __NR_restart_syscall:
        case __NR_sched_getaffinity:
        case __NR_getpid:
        case __NR_gettid:

        // random
        case __NR_getrandom:
        case __NR_readlink:
            break;

        // file I/O
        case __NR_lseek:
        case __NR_write:
        case __NR_read:
        case __NR_sendto:
        case __NR_recvfrom:
        case __NR_sendmsg:
        case __NR_recvmsg:
        case __NR_fstat:
        case __NR_fcntl:
        case __NR_readlinkat: {
            if(regs.rdi <= 3 || regs.rdi == AT_FDCWD) break;

            auto desc = process->io_map.get_file_description(regs.rdi);
            if(!desc) {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EINVAL;
                break;
            }
            if(desc->user) {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SEND_SIGSYS;
                break;
            }
            break;
        }

        case __NR_dup3:
        case __NR_dup2:
        case __NR_dup: {
            auto desc = process->io_map.get_file_description(regs.rdi);
            if(!desc) {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EINVAL;
                break;
            }
            bool user = desc->user;
            auto path = desc->path;
            int flags = desc->flags;
            if(nr == __NR_dup3) flags |= (int) regs.rdx;
            deferred.push_back([this, user, path(std::move(path)), flags](user_regs_struct& regs) {
                if(regs.rax >= 0) {
                    process->insert_fd(regs.rax, user, path, flags);
                }
                return false;
            });
            break;
        }

        case __NR_close: {
            int fd = regs.rdi;
            deferred.push_back([this, fd](user_regs_struct& regs) {
                if(regs.rax == 0) {
                    process->io_map.remove_file_description(fd);
                }
                return false;
            });
            break;
        }

        // Only allow `clone` to create threads, but not full processes.
        case __NR_clone: {
            static const int allowed_flags =
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID |
                CLONE_DETACHED;
            static const int required_flags = CLONE_VM | CLONE_THREAD;

            if((regs.rdi & (~allowed_flags)) != 0 || (regs.rdi & required_flags) != required_flags) {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EPERM;
                auto ck_pid_s = stringify_ck_pid(this->process->ck_pid);
                printf("Warning: Thread %d/%d/%s is trying to call clone() with disallowed flags.\n", this->process->os_pid, this->os_tid, ck_pid_s.c_str());
                break;
            } else {

            }
            break;
        }

        case __NR_openat: {
            if(auto desc = process->io_map.get_file_description(regs.rdi)) {
                if(auto maybe_path = read_c_string(regs.rsi, 65536)) {
                    std::string path = std::move(maybe_path.value());
                    int flags = regs.rdx;
                    deferred.push_back([this, dirfd(std::move(desc)), path(std::move(path)), flags](user_regs_struct& regs) {
                        return register_returned_fd_after_syscall(regs, dirfd->path, path, flags);
                    });
                } else {
                    is_invalid = true;
                    fixup_method = SyscallFixupMethod::SET_VALUE;
                    replace_value = -EFAULT;
                }
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EINVAL;
            }
            break;
        }
        case __NR_open: {
            if(auto maybe_path = read_c_string(regs.rdi, 65536)) {
                std::string path = std::move(maybe_path.value());
                int flags = regs.rsi;
                deferred.push_back([this, path(std::move(path)), flags](user_regs_struct& regs) {
                    return register_returned_fd_after_syscall(regs, {}, path, flags);
                });
            } else {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EFAULT;
            }
            break;
        }

        case CK_SYS_GET_ABI_VERSION: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = CK_ABI_VERSION;
            break;
        }
        case CK_SYS_NOTIFY_INVALID_SYSCALL: {
            process->notify_invalid_syscall.store(true);
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = 0;
            break;
        }
        case CK_SYS_MARK_FD_AS_USER: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;

            auto desc_p = process->io_map.get_file_description(regs.rdi);
            if(!desc_p) {
                replace_value = -EINVAL;
            } else {
                FileDescription desc = *desc_p;
                desc.user = true;
                process->io_map.insert_file_description(regs.rdi, std::shared_ptr<FileDescription>(new FileDescription(std::move(desc))));
                replace_value = 0;
            }

            break;
        }
        case CK_SYS_LOAD_PROCESSOR_STATE_AND_UNMAP_LOADER: {
            user_regs_struct new_regs;
            if(!process->read_memory(regs.rdi, sizeof(new_regs), (uint8_t *) &new_regs)) {
                is_invalid = true;
                fixup_method = SyscallFixupMethod::SET_VALUE;
                replace_value = -EINVAL;
                break;
            }
            new_regs.rax = 0;

            regs.orig_rax = __NR_munmap;
            regs.rdi = 0x70000000;
            regs.rsi = 0x10000000;
            ptrace(PTRACE_SETREGS, os_tid, 0, &regs);

            deferred.push_back([this, new_regs](user_regs_struct& regs) {
                // FIXME: Will all registers always be set to the provided value successfully?
                ptrace(PTRACE_SETREGS, os_tid, 0, &new_regs);
                ptrace(PTRACE_GETREGS, os_tid, 0, &regs);
                return false;
            });
            break;
        }
        case CK_SYS_SNAPSHOT_ME: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = -EINVAL;

            auto snapshot = this->process->take_snapshot();
            if(!snapshot) {
                break;
            }

            {
                std::lock_guard<std::mutex> lg(this->process->last_snapshot_mu);
                this->process->last_snapshot = std::move(snapshot);
            }
            replace_value = 1;
            break;
        }
        case CK_SYS_GETPID: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;

            __uint128_t pid = process->ck_pid;
            if(process->write_memory(regs.rdi, 16, (uint8_t *) &pid)) replace_value = 0;
            else replace_value = -EFAULT;
            break;
        }
        case CK_SYS_DEBUG_PRINT_REGS: {
            is_invalid = true;
            fixup_method = SyscallFixupMethod::SET_VALUE;
            replace_value = 0;
            print_regs(regs);
            break;
        }
        default:
            if(permissive_mode) {
                auto ck_pid_s = stringify_ck_pid(this->process->ck_pid);
                printf("Warning (permissive mode): Process %d/%d/%s invoked an unknown syscall: %lu\n", this->process->os_pid, this->os_tid, ck_pid_s.c_str(), nr);
            } else {
                is_invalid = true;
                if(process->notify_invalid_syscall.load()) {
                    fixup_method = SyscallFixupMethod::SEND_SIGSYS;
                } else {
                    printf("Invalid syscall: %lu\n", nr);
                    fixup_method = SyscallFixupMethod::SET_VALUE;
                    replace_value = -EPERM;
                }
            }
            break;
    }

    if(is_invalid) {
        regs.orig_rax = __NR_getpid;
        ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
    }

    ptrace(PTRACE_SYSCALL, os_tid, 0, 0);
    int wstatus = 0;
    if(waitpid(os_tid, &wstatus, 0) < 0) return TraceContinuationState::BREAK;

    int stopsig = WSTOPSIG(wstatus);
    if(WIFEXITED(wstatus) || WIFSIGNALED(wstatus)) {
        return TraceContinuationState::BREAK;
    }

    stopsig = WSTOPSIG(wstatus);
    ptrace(PTRACE_GETREGS, os_tid, 0, &regs);
    
    if(!is_invalid) {
        for(auto it = deferred.rbegin(); it != deferred.rend(); it++) {
            is_invalid = (*it)(regs);
            if(is_invalid) {
                fixup_method = SyscallFixupMethod::SEND_SIGSYS;
                break;
            }
        }
    }

    if((wstatus >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
        return handle_new_thread();
    }

    if(stopsig == (SIGTRAP | 0x80)) {
        if(is_invalid) {
            switch(fixup_method) {
                case SyscallFixupMethod::SET_VALUE: {
                    regs.rax = replace_value;
                    ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
                    break;
                }
                case SyscallFixupMethod::SEND_SIGSYS: {
                    regs.rax = nr;
                    ptrace(PTRACE_SETREGS, os_tid, 0, &regs);
                    tgkill(this->process->os_pid, this->os_tid, SIGSYS);
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

TraceContinuationState Thread::handle_signal(user_regs_struct regs, int& sig) {
    if(sig == SIGTRAP && this->process->sandbox_state.load() == SandboxState::IN_EXEC) {
        sig = 0;
        this->process->sandbox_state.store(SandboxState::IN_SANDBOX);
    }
    return TraceContinuationState::CONTINUE;
}

TraceContinuationState Thread::handle_new_thread() {
    unsigned long new_tid = 0;
    if(ptrace(PTRACE_GETEVENTMSG, os_tid, 0, &new_tid) < 0) {
        printf("Unable to get message for CLONE event\n");
        return TraceContinuationState::BREAK;
    }
    assert(new_tid > 0);
    assert(waitpid(new_tid, nullptr, 0) >= 0);
    if(ptrace(PTRACE_DETACH, new_tid, 0, SIGSTOP) < 0) {
        printf("Unable to detach from the new thread\n");
        return TraceContinuationState::BREAK;
    }

    std::promise<void> creation_done;
    std::future<void> creation_done_fut = creation_done.get_future();
    std::thread([process(this->process), &creation_done, new_tid]() {
        if(ptrace(PTRACE_ATTACH, new_tid, 0, 0) < 0) {
            try {
                throw std::runtime_error("unable to attach to the new thread");
            } catch(...) {
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
    } catch(std::runtime_error& e) {
        printf("Thread creation failed: %s\n", e.what());
    }
    return TraceContinuationState::CONTINUE;
}

void Process::insert_fd(int fd, bool user, const std::filesystem::path& path, int flags) {
    auto desc = std::shared_ptr<FileDescription>(new FileDescription);
    desc->user = user;
    desc->path = path;
    desc->flags = flags;
    io_map.insert_file_description(fd, std::move(desc));
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
    // Destructor calls are deferred to after releasing `this->mu` to prevent deadlocking.
    std::vector<std::shared_ptr<Process>> deleted;

    {
        std::lock_guard<std::mutex> lg(this->mu);

        for(auto pid : pending_termination) {
            auto it = processes.find(pid);
            if(it != processes.end()) {
                deleted.push_back(it->second);
                processes.erase(it);
            }
        }

        pending_termination.clear();
    }
}

ProcessSet global_process_set;
