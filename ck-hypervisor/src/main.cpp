#include <ck-hypervisor/network.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/profile.h>
#include <ck-hypervisor/registry.h>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

static std::atomic<bool> got_interrupt(false);

void handle_interrupt(int signo) { got_interrupt.store(true); }
void handle_sigusr1(int signo) {}

int main(int argc, const char *argv[]) {
  signal(SIGINT, handle_interrupt);
  signal(SIGTERM, handle_interrupt);
  signal(SIGUSR1, handle_sigusr1); // "explicitly" ignore to ensure EINTR delivery.

  if (const char *config_path = getenv("CK_CONFIG")) {
    std::ifstream config_file(config_path);
    if (!config_file) {
      printf("cannot open config file\n");
      exit(1);
    }
    std::string config_data;
    char c = '\0';
    while (config_file.get(c))
      config_data.push_back(c);
    if (!global_profile.parse(config_data)) {
      printf("cannot parse config file\n");
      exit(1);
    }
  } else {
    printf("CK_CONFIG environmental variable required\n");
    exit(1);
  }

  if (getuid() != 0) {
    printf("must be run with root\n");
    exit(1);
  }

  global_registry.set_prefix(global_profile.module_path.c_str());
  global_router.setup_tun();
  std::thread([]() { global_router.run_loop(); }).detach();

  {
    std::shared_lock<std::shared_mutex> lg(global_profile_mu);
    for (auto &[k, app] : global_profile.apps) {
      Process *raw_proc = nullptr;
      try {
        raw_proc = new Process(app);
      } catch (std::runtime_error &e) {
        printf("Unable to start process %s: %s\n", app->name.c_str(), e.what());
        continue;
      }
      std::shared_ptr<Process> proc(raw_proc);
      auto ck_pid = global_process_set.attach_process(proc);
      proc->run();
    }
  }

  while (true) {
    usleep(50000); // 50ms
    if (got_interrupt.load()) {
      got_interrupt.store(false);
      global_process_set.for_each_process([](std::shared_ptr<Process> &proc) {
        proc->kill_async();
        return true;
      });
    }
    global_process_set.tick();
    if (global_process_set.get_num_processes() == 0)
      break;
  }

  printf("All processes exited, stopping hypervisor.\n");
  sleep(1);

  return 0;
}
