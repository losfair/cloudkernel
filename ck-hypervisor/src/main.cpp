#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <vector>
#include <string>
#include <unistd.h>
#include <ck-hypervisor/sandbox.h>
#include <ck-hypervisor/process.h>
#include <ck-hypervisor/registry.h>

int main(int argc, const char *argv[]) {
    if(argc == 1) {
        std::cout << "Invalid arguments" << std::endl;
        exit(1);
    }

    if(const char *prefix = getenv("CK_MODULE_PREFIX")) {
        global_registry.set_prefix(prefix);
    }

    std::vector<std::string> args;
    for(int i = 1; i < argc; i++) {
        args.push_back(argv[i]);
    }

    std::shared_ptr<Process> init_proc(new Process(args));
    init_proc->privileged = true;
    auto ck_pid = global_process_set.attach_process(init_proc);
    init_proc->run();

    while(true) {
        sleep(1);
        if(global_process_set.get_process(ck_pid) == nullptr) break;
    }

    return 0;
}
