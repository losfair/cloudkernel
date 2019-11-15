#include <ck-hypervisor/network.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/registry.h>
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

int main(int argc, const char *argv[]) {
  signal(SIGINT, handle_interrupt);
  signal(SIGTERM, handle_interrupt);

  if (argc == 1) {
    printf("Invalid arguments\n");
    exit(1);
  }

  if (const char *prefix = getenv("CK_MODULE_PREFIX")) {
    global_registry.set_prefix(prefix);
  }

  global_router.setup_tun();
  std::thread([]() { global_router.run_loop(); }).detach();

  std::vector<std::string> args;
  for (int i = 1; i < argc; i++) {
    args.push_back(argv[i]);
  }

  std::shared_ptr<Process> init_proc(new Process(args));
  auto ck_pid = global_process_set.attach_process(init_proc);
  init_proc->run();

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
