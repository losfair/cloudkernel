#include <ck-hypervisor/linking.h>
#include <ck-hypervisor/registry.h>
#include <sys/mman.h>
#include <vector>
#include <unistd.h>
#include <iterator>
#include <stdexcept>
#include <fcntl.h>
#include <stdlib.h>
#include <map>
#include <string>
#include <mutex>
#include <iostream>
#include <string.h>
#include <stdio.h>

DynamicModule::DynamicModule(const char *name, VersionCode version) {
    module_handle = global_registry.get_module(name, version);
    module_type = module_handle->module_type;
    module_size = module_handle->get_file_size();
    fd = module_handle->module_fd;
}

DynamicModule::~DynamicModule() {
    // `fd` is closed by `module_handle` destructor
}
