#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <unistd.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/registry.h>
#include <ck-hypervisor/network.h>

int main(int argc, const char *argv[]) {
    if(argc == 1) {
        std::cout << "Invalid arguments" << std::endl;
        exit(1);
    }

    if(const char *prefix = getenv("CK_MODULE_PREFIX")) {
        global_registry.set_prefix(prefix);
    }

    global_router.setup_tun();
    std::thread([]() {
        global_router.run_loop();
    }).detach();

    std::vector<std::string> args;
    for(int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }

    std::shared_ptr<Process> init_proc(new Process(args));
    init_proc->privileged = true;
    auto ck_pid = global_process_set.attach_process(init_proc);
    init_proc->run();

    while(true) {
        usleep(50000); // 50ms
        global_process_set.tick();
        if(global_process_set.get_process(ck_pid) == nullptr) break;
    }

    return 0;
}
