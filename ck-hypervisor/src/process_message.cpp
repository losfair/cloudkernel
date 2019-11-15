#include <ck-hypervisor/config.h>
#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/message.h>
#include <ck-hypervisor/network.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/process_api.h>
#include <ck-hypervisor/registry.h>
#include <fcntl.h>
#include <picosha2.h>
#include <unistd.h>

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

static void send_invalid(int socket) {
  Message msg;
  msg.sender_or_recipient = (__uint128_t)(__int128_t)-1;
  msg.session = (uint64_t)(int64_t)-1;
  msg.tag = (MessageType)(int32_t)-1;
  msg.body = nullptr;
  msg.body_len = 0;
  msg.send(socket);
}

void Process::handle_kernel_message(uint64_t session, MessageType tag,
                                    uint8_t *data, size_t rem) {
  if (session != 0) {
    send_reject(socket, "invalid kernel session");
    return;
  }
  switch (tag) {
  case MessageType::MODULE_REQUEST: {
    std::string full_name((const char *)data, rem);
    auto maybe_name_info = parse_module_full_name(full_name.c_str());
    if (!maybe_name_info) {
      printf("handle_kernel_message: MODULE_REQUEST: Invalid module full name: "
             "%s\n",
             full_name.c_str());
      send_reject(socket, "invalid module name");
      break;
    }
    auto name_info = std::move(maybe_name_info.value());
    auto module_name = std::move(name_info.first);
    auto version_code = name_info.second;
    std::string module_type = "";

    std::shared_ptr<DynamicModule> dm;
    try {
      dm = std::shared_ptr<DynamicModule>(
          new DynamicModule(module_name.c_str(), version_code));
      module_type = dm->module_type;
    } catch (std::runtime_error &e) {
      printf("Error while trying to get module '%s': %s\n", module_name.c_str(),
             e.what());
      send_reject(socket, "missing/invalid module");
      break;
    }

    // We cannot pass the DynamicModule fd back directly because we want
    // syscalls like `lseek` to be independent.
    std::stringstream fd_handle_path_ss;
    fd_handle_path_ss << "/proc/" << getpid() << "/fd/" << dm->fd;
    std::string fd_handle_path = fd_handle_path_ss.str();
    int fd_handle = open(fd_handle_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd_handle < 0) {
      send_reject(socket, "cannot open fd");
      break;
    }

    Message msg;
    msg.tag = MessageType::MODULE_OFFER;
    msg.body = (const uint8_t *)&module_type[0];
    msg.body_len = module_type.size();

    FdSet fds;
    fds.add(fd_handle);
    msg.fds = &fds;
    msg.send(socket);

    break;
  }
  case MessageType::PROCESS_CREATE: {
    if (rem != sizeof(ProcessCreationInfo)) {
      send_reject(socket);
      break;
    }

    ProcessCreationInfo info;
    std::copy(data, data + sizeof(ProcessCreationInfo), (uint8_t *)&info);

    if (info.api_version != APIVER_ProcessCreationInfo) {
      send_reject(socket, "api version mismatch");
      break;
    }

    if (info.argc == 0 || info.argc > 256) {
      send_reject(socket, "invalid number of arguments");
      break;
    }

    std::vector<RemoteString> argv_rptr(info.argc);
    if (!read_memory(info.argv, argv_rptr.size() * sizeof(RemoteString),
                     (uint8_t *)&argv_rptr[0])) {
      send_reject(socket, "unable to read arguments");
      break;
    }

    std::vector<std::string> argv(argv_rptr.size());

    {
      bool rejected = false;
      for (size_t i = 0; i < argv_rptr.size(); i++) {
        if (argv_rptr[i].len > 65536) {
          send_reject(socket, "argument too long");
          rejected = true;
          break;
        }
        if (argv_rptr[i].len == 0)
          continue;
        argv[i] = std::string(argv_rptr[i].len, '\0');
        read_memory(argv_rptr[i].rptr, argv_rptr[i].len,
                    (uint8_t *)&argv[i][0]);
      }
      if (rejected)
        break;
    }

    std::shared_ptr<Process> new_proc(new Process(argv));
    new_proc->parent_ck_pid = this->ck_pid;

    global_process_set.attach_process(new_proc);
    auto new_pid = new_proc->ck_pid;
    try {
      new_proc->run();
    } catch (std::runtime_error &e) {
      global_process_set.notify_termination(new_pid);
      send_reject(socket, "cannot create process");
      break;
    }

    ProcessOffer offer;
    offer.api_version = APIVER_ProcessOffer;
    offer.pid = new_pid;

    Message offer_msg;
    offer_msg.tag = MessageType::PROCESS_OFFER;
    offer_msg.body = (const uint8_t *)&offer;
    offer_msg.body_len = sizeof(offer);

    send_ok(socket);
    offer_msg.send(socket);

    break;
  }
  case MessageType::DEBUG_PRINT: {
    std::string message((const char *)data, rem);
    auto ck_pid_s = stringify_ck_pid(this->ck_pid);
    printf("[%s] %s\n", ck_pid_s.c_str(), message.c_str());
    break;
  }
  case MessageType::PROCESS_WAIT: {
    if (rem < sizeof(ProcessWait)) {
      send_reject(socket);
      break;
    }

    ProcessWait info;
    std::copy(data, data + sizeof(ProcessWait), (uint8_t *)&info);

    auto remote_proc = global_process_set.get_process(info.pid);
    if (!remote_proc) {
      send_reject(socket, "process not found");
      break;
    }

    auto remote_pid = info.pid;
    auto this_pid = this->ck_pid;
    remote_proc->add_awaiter([&]() {
      if (auto proc = global_process_set.get_process(this_pid)) {
        OwnedMessage msg;
        msg.tag = MessageType::PROCESS_COMPLETION;
        msg.body = std::vector<uint8_t>((const uint8_t *)&remote_pid,
                                        (const uint8_t *)&remote_pid +
                                            sizeof(remote_pid));
        proc->pending_messages.push(std::move(msg));
      }
    });
    {
      auto _x = std::move(remote_proc); // drop
    }
    send_ok(socket);
    break;
  }
  case MessageType::POLL: {
    if (rem < sizeof(uint64_t)) {
      send_invalid(socket);
      break;
    }
    uint64_t millis = *(uint64_t *)data;
    if (auto maybe_msg =
            (millis == 0 ? pending_messages.pop()
                         : pending_messages.timed_pop(
                               std::chrono::milliseconds(millis)))) {
      auto msg = std::move(maybe_msg.value());
      auto out = msg.borrow();
      out.send(socket);
    } else {
      send_invalid(socket);
    }
    break;
  }
  /*
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
      bool registered = global_process_set.register_service(std::move(name),
  this->ck_pid);

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
  */
  case MessageType::IP_PACKET: {
    if (rem == 0 || rem > 1500)
      break;
    global_router.dispatch_packet(data, rem);
    break;
  }
  case MessageType::IP_ADDRESS_REGISTER_V4: {
    if (rem != 4) {
      send_reject(socket, "invalid address length");
      break;
    }

    uint32_t addr = *(uint32_t *)data;
    std::reverse((uint8_t *)&addr, ((uint8_t *)&addr) + 4);
    __uint128_t full_addr =
        ((__uint128_t)0xffff00000000ull) | (__uint128_t)addr;

    auto endpoint = std::shared_ptr<RoutingEndpoint>(new RoutingEndpoint);

    // This function can be recursively called within another
    // `handle_kernel_message`. Make sure locks are held properly.
    endpoint->on_packet = [full_addr, ck_pid(this->ck_pid)](uint8_t *data,
                                                            size_t len) {
      if (auto proc = global_process_set.get_process(ck_pid)) {
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
  case MessageType::SNAPSHOT_CREATE: {
    if (rem != sizeof(__uint128_t)) {
      send_reject(socket, "invalid pid size");
      break;
    }

    __uint128_t pid = *(__uint128_t *)data;
    auto target_proc = global_process_set.get_process(pid);
    if (!target_proc) {
      send_reject(socket, "process not found");
      break;
    }

    auto snapshot = target_proc->take_snapshot();
    if (!snapshot) {
      send_reject(socket, "unable to take snapshot");
      break;
    }

    std::vector<uint8_t> snapshot_hash_bytes(picosha2::k_digest_size);
    picosha2::hash256(snapshot->begin(), snapshot->end(),
                      snapshot_hash_bytes.begin(), snapshot_hash_bytes.end());

    std::string snapshot_name = "snapshot:";
    snapshot_name += picosha2::bytes_to_hex_string(snapshot_hash_bytes.begin(),
                                                   snapshot_hash_bytes.end());

    try {
      global_registry.save_module(snapshot_name.c_str(), std::nullopt,
                                  "snapshot", &(*snapshot)[0],
                                  snapshot->size());
    } catch (std::runtime_error &e) {
      send_reject(socket, "unable to save snapshot");
      break;
    }

    send_ok(socket, snapshot_name.c_str());
    break;
  }
  default:
    break; // invalid tag
  }
}