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

    Process init_proc(args);
    init_proc.no_kill_at_destruction = true;

    return 0;
}
